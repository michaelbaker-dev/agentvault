//! End-to-end tests through the real router, with a fake tailnet.

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode, header},
};
use serde_json::{Value, json};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::sync::Semaphore;
use tower::ServiceExt;

use crate::app::{App, AppRef};
use crate::auth::{LoginLimiter, Sessions};
use crate::config::{Config, Describe, Tls, Unlock};
use crate::db::Db;
use crate::identity::{Caller, Resolver};
use crate::server::router;
use crate::vault::{TEST_KDF, Vault};

const HOST: &str = "keys.test.ts.net:8443";
const ORIGIN: &str = "https://keys.test.ts.net:8443";
const OWNER: &str = "owner@example.com";
const LAPTOP: &str = "100.64.0.1";
const SPARK: &str = "100.64.0.2";
const TAGGED: &str = "100.64.0.3";
const FRIEND: &str = "100.64.0.4";
const OUTSIDER: &str = "192.168.1.50";
const PASS: &str = "correct horse battery staple";

/// Builds fake credentials at runtime so secret scanners don't flag the test file.
fn fake(prefix: &str, c: char, n: usize) -> String {
    format!("{prefix}{}", c.to_string().repeat(n))
}

fn caller(ip: &str, node: &str, user: &str, tags: &[&str]) -> (std::net::IpAddr, Caller) {
    let ip = ip.parse().unwrap();
    (
        ip,
        Caller {
            ip,
            node_id: format!("n{node}"),
            node: node.into(),
            node_fqdn: format!("{node}.test.ts.net"),
            user: user.into(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
        },
    )
}

fn test_app() -> AppRef {
    test_app_with(Default::default())
}

fn test_app_with(endpoints: crate::rotate::Endpoints) -> AppRef {
    let peers: HashMap<_, _> = [
        caller(LAPTOP, "laptop", OWNER, &[]),
        caller(SPARK, "server", OWNER, &[]),
        caller(TAGGED, "ci-runner", "tagged-devices", &["tag:agent"]),
        caller(FRIEND, "friend-pc", "friend@example.com", &[]),
    ]
    .into_iter()
    .collect();
    let cfg = Config {
        listen: "100.64.0.10:8443".parse().unwrap(),
        hostname: "keys.test.ts.net".into(),
        owner: OWNER.into(),
        data_dir: "/nonexistent-test-data".into(),
        tailscale_socket: "/nonexistent".into(),
        tls: Tls {
            cert_file: "/x".into(),
            key_file: "/x".into(),
            renew_with_tailscale: false,
        },
        describe: Describe {
            verify_with_provider: false,
            claude_secret: None,
            model: "claude-opus-5-5".into(),
        },
        unlock: Unlock::default(),
        event_retention_days: 30,
        rotation: Default::default(),
    };
    Arc::new(App {
        origin: cfg.origin(),
        cfg,
        db: Arc::new(Db::memory().unwrap()),
        vault: Vault::default(),
        sessions: Sessions::default(),
        limiter: LoginLimiter::default(),
        resolver: Resolver::Fixed(peers),
        http: reqwest::Client::new(),
        kdf: TEST_KDF,
        kdf_gate: Semaphore::new(2),
        denied_budget: Default::default(),
        imports: Default::default(),
        describe_gate: Semaphore::new(4),
        minted: Default::default(),
        endpoints,
        auto_unlock: Default::default(),
        stations: Default::default(),
    })
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

async fn call(app: &AppRef, ip: &str, method: &str, path: &str, hdrs: &[(&str, &str)], body: Option<Value>) -> Resp {
    let mut req = Request::builder().method(method).uri(path).header(header::HOST, HOST);
    for (k, v) in hdrs {
        req = req.header(*k, *v);
    }
    let body = match body {
        Some(b) => {
            req = req.header(header::CONTENT_TYPE, "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    let mut req = req.body(body).unwrap();
    let addr: SocketAddr = format!("{ip}:55555").parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(addr));
    let resp = router(app.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), 10 << 20).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Resp { status, headers, body }
}

/// Owner session: (cookie header value, csrf).
struct Session {
    cookie: String,
    csrf: String,
}

impl Session {
    fn hdrs(&self) -> Vec<(&str, &str)> {
        vec![("cookie", self.cookie.as_str()), ("x-agentvault-csrf", self.csrf.as_str())]
    }
}

fn session_from(r: &Resp) -> Session {
    let set = r.headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
    assert!(set.contains("HttpOnly") && set.contains("Secure") && set.contains("SameSite=Strict"));
    Session {
        cookie: set.split(';').next().unwrap().to_string(),
        csrf: r.body["csrf"].as_str().unwrap().to_string(),
    }
}

async fn setup(app: &AppRef) -> Session {
    let r = call(app, LAPTOP, "POST", "/v1/setup", &[], Some(json!({ "passphrase": PASS }))).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    session_from(&r)
}

async fn add(app: &AppRef, s: &Session, name: &str, value: &str) {
    let r = call(
        app,
        LAPTOP,
        "POST",
        "/v1/secrets",
        &s.hdrs(),
        Some(json!({ "name": name, "value": value, "verify": false })),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
}

async fn token(app: &AppRef, s: &Session, scopes: &[&str], secrets: &[&str], nodes: &[&str]) -> String {
    let r = call(
        app,
        LAPTOP,
        "POST",
        "/v1/tokens",
        &s.hdrs(),
        Some(json!({ "name": "test", "scopes": scopes, "secrets": secrets, "nodes": nodes })),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    format!("Bearer {}", r.body["token"].as_str().unwrap())
}

#[tokio::test]
async fn network_guards() {
    let app = test_app();
    let r = call(&app, OUTSIDER, "GET", "/v1/status", &[], None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "non-tailnet address must be refused");

    let mut req = Request::builder()
        .uri("/v1/status")
        .header(header::HOST, "evil.example")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo::<SocketAddr>(format!("{LAPTOP}:1").parse().unwrap()));
    let resp = router(app.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST, "DNS-rebinding Host must be refused");

    let r = call(&app, LAPTOP, "GET", "/v1/status", &[("origin", "https://evil.example")], None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "cross-origin browser requests must be refused");

    let r = call(&app, LAPTOP, "GET", "/v1/status", &[("origin", ORIGIN)], None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["caller"]["node"], "laptop");
    assert!(r.headers.get("content-security-policy").is_some());
    assert_eq!(r.headers.get("cache-control").unwrap(), "no-store");
}

#[tokio::test]
async fn only_owner_devices_can_set_up_or_sign_in() {
    let app = test_app();
    for ip in [TAGGED, FRIEND] {
        let r = call(&app, ip, "POST", "/v1/setup", &[], Some(json!({ "passphrase": PASS }))).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);
    }
    let r = call(&app, LAPTOP, "POST", "/v1/setup", &[], Some(json!({ "passphrase": "short" }))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    setup(&app).await;
    let r = call(&app, LAPTOP, "POST", "/v1/setup", &[], Some(json!({ "passphrase": PASS }))).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "setup can't run twice");
    let r = call(&app, FRIEND, "POST", "/v1/session", &[], Some(json!({ "passphrase": PASS }))).await;
    assert_eq!(
        r.status,
        StatusCode::FORBIDDEN,
        "the passphrase alone isn't enough from someone else's device"
    );
}

#[tokio::test]
async fn session_needs_csrf_and_stays_on_its_device() {
    let app = test_app();
    let s = setup(&app).await;
    add(&app, &s, "OPENAI_API_KEY", &fake("sk-proj-", 'q', 36)).await;

    let r = call(
        &app,
        LAPTOP,
        "GET",
        "/v1/secrets/OPENAI_API_KEY/value",
        &[("cookie", &s.cookie)],
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "cookie without CSRF header");
    let r = call(
        &app,
        LAPTOP,
        "GET",
        "/v1/secrets/OPENAI_API_KEY/value",
        &[("cookie", &s.cookie), ("x-agentvault-csrf", "nope")],
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "wrong CSRF header");
    let r = call(&app, LAPTOP, "GET", "/v1/secrets/OPENAI_API_KEY/value", &s.hdrs(), None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["value"], fake("sk-proj-", 'q', 36));

    // Same owner, different machine (e.g. an agent on the server that found the cookie).
    let r = call(&app, SPARK, "GET", "/v1/secrets/OPENAI_API_KEY/value", &s.hdrs(), None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // Network identity alone, with no credential, gets nothing.
    let r = call(&app, LAPTOP, "GET", "/v1/secrets", &[], None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn crud_rename_versions_and_delete() {
    let app = test_app();
    let s = setup(&app).await;
    add(&app, &s, "GH", &fake("ghp_", 'a', 36)).await;
    let r = call(
        &app,
        LAPTOP,
        "POST",
        "/v1/secrets",
        &s.hdrs(),
        Some(json!({ "name": "GH", "value": "x" })),
    )
    .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = call(
        &app,
        LAPTOP,
        "POST",
        "/v1/secrets",
        &s.hdrs(),
        Some(json!({ "name": "../etc", "value": "x" })),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    let r = call(
        &app,
        LAPTOP,
        "PATCH",
        "/v1/secrets/GH",
        &s.hdrs(),
        Some(json!({ "name": "GITHUB_TOKEN", "value": fake("ghp_", 'b', 36), "notes": "CI pushes", "tags": ["ci"], "verify": false })),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["name"], "GITHUB_TOKEN");
    assert_eq!(r.body["version"], 2);
    assert_eq!(r.body["tags"], json!(["ci"]));
    let r = call(&app, LAPTOP, "GET", "/v1/secrets/GITHUB_TOKEN/value", &s.hdrs(), None).await;
    assert_eq!(r.body["value"], fake("ghp_", 'b', 36));
    assert_eq!(
        call(&app, LAPTOP, "GET", "/v1/secrets/GH", &s.hdrs(), None).await.status,
        StatusCode::NOT_FOUND
    );

    // Describer runs in the background; give it a moment.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let r = call(&app, LAPTOP, "GET", "/v1/secrets/GITHUB_TOKEN", &s.hdrs(), None).await;
    assert_eq!(r.body["provider"], "github");
    assert_eq!(r.body["risk"], "high");
    assert_eq!(r.body["proxy_ready"], true);
    assert!(r.body.get("value").is_none(), "metadata never carries the value");

    let r = call(&app, LAPTOP, "DELETE", "/v1/secrets/GITHUB_TOKEN", &s.hdrs(), None).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = call(&app, LAPTOP, "GET", "/v1/secrets", &s.hdrs(), None).await;
    assert_eq!(r.body["secrets"], json!([]));
}

#[tokio::test]
async fn token_scopes_globs_pinning_and_revocation() {
    let app = test_app();
    let s = setup(&app).await;
    add(&app, &s, "OPENAI_API_KEY", &fake("sk-proj-", 'q', 36)).await;
    add(&app, &s, "STRIPE_LIVE", &fake("sk_live_", 'z', 24)).await;

    let agent = token(&app, &s, &["list", "proxy"], &["OPENAI_*"], &[]).await;
    let h = [("authorization", agent.as_str())];
    let r = call(&app, SPARK, "GET", "/v1/secrets", &h, None).await;
    assert_eq!(r.status, StatusCode::OK);
    let names: Vec<_> = r.body["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, vec!["OPENAI_API_KEY"], "globs hide other secrets");
    assert_eq!(
        call(&app, SPARK, "GET", "/v1/secrets/OPENAI_API_KEY/value", &h, None).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&app, SPARK, "GET", "/v1/secrets/STRIPE_LIVE", &h, None).await.status,
        StatusCode::FORBIDDEN
    );
    let r = call(
        &app,
        SPARK,
        "POST",
        "/v1/secrets",
        &h,
        Some(json!({ "name": "OPENAI_X", "value": "v" })),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(
        call(&app, SPARK, "GET", "/v1/tokens", &h, None).await.status,
        StatusCode::FORBIDDEN,
        "tokens can't manage tokens"
    );
    assert_eq!(
        call(&app, SPARK, "GET", "/v1/dashboard", &h, None).await.status,
        StatusCode::FORBIDDEN
    );

    // A writer token still can't redirect the proxy (that would leak the key).
    let writer = token(&app, &s, &["write"], &["*"], &[]).await;
    let r = call(
        &app,
        SPARK,
        "PATCH",
        "/v1/secrets/OPENAI_API_KEY",
        &[("authorization", writer.as_str())],
        Some(json!({ "proxy": { "base_url": "https://attacker.example" } })),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    let pinned = token(&app, &s, &["read"], &["*"], &["laptop"]).await;
    assert_eq!(
        call(
            &app,
            SPARK,
            "GET",
            "/v1/secrets/STRIPE_LIVE/value",
            &[("authorization", pinned.as_str())],
            None
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    let r = call(
        &app,
        LAPTOP,
        "GET",
        "/v1/secrets/STRIPE_LIVE/value",
        &[("authorization", pinned.as_str())],
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["value"], fake("sk_live_", 'z', 24));

    let list = call(&app, LAPTOP, "GET", "/v1/tokens", &s.hdrs(), None).await;
    let id = list.body["tokens"][0]["id"].as_i64().unwrap();
    assert!(!list.body.to_string().contains("kt_"), "token list never shows token values");
    assert_eq!(
        call(&app, LAPTOP, "DELETE", &format!("/v1/tokens/{id}"), &s.hdrs(), None)
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &app,
            LAPTOP,
            "GET",
            "/v1/secrets/STRIPE_LIVE/value",
            &[("authorization", pinned.as_str())],
            None
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, LAPTOP, "GET", "/v1/secrets", &[("authorization", "Bearer kt_forged")], None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn sealing_and_lockout() {
    let app = test_app();
    let s = setup(&app).await;
    add(&app, &s, "K", "value-123456789").await;
    let reader = token(&app, &s, &["read"], &["*"], &[]).await;

    assert_eq!(call(&app, LAPTOP, "POST", "/v1/seal", &s.hdrs(), None).await.status, StatusCode::OK);
    let r = call(
        &app,
        SPARK,
        "GET",
        "/v1/secrets/K/value",
        &[("authorization", reader.as_str())],
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE, "sealed vault can't decrypt");
    assert_eq!(
        call(&app, LAPTOP, "GET", "/v1/secrets", &s.hdrs(), None).await.status,
        StatusCode::UNAUTHORIZED,
        "sealing signs everyone out"
    );

    for _ in 0..5 {
        let r = call(
            &app,
            LAPTOP,
            "POST",
            "/v1/session",
            &[],
            Some(json!({ "passphrase": "wrong passphrase!" })),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    let r = call(&app, LAPTOP, "POST", "/v1/session", &[], Some(json!({ "passphrase": PASS }))).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "locked out even with the right passphrase");

    let r = call(&app, SPARK, "POST", "/v1/session", &[], Some(json!({ "passphrase": PASS }))).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = call(
        &app,
        SPARK,
        "GET",
        "/v1/secrets/K/value",
        &[("authorization", reader.as_str())],
        None,
    )
    .await;
    assert_eq!(r.body["value"], "value-123456789");
}

#[tokio::test]
async fn usage_is_recorded_and_tamper_evident() {
    let app = test_app();
    let s = setup(&app).await;
    add(&app, &s, "K", "value-123456789").await;
    let reader = token(&app, &s, &["read"], &["*"], &[]).await;
    for _ in 0..3 {
        call(
            &app,
            SPARK,
            "GET",
            "/v1/secrets/K/value",
            &[("authorization", reader.as_str())],
            None,
        )
        .await;
    }
    call(&app, FRIEND, "GET", "/v1/secrets/K/value", &[], None).await;

    let d = call(&app, LAPTOP, "GET", "/v1/dashboard?range=24h", &s.hdrs(), None).await;
    assert_eq!(d.status, StatusCode::OK);
    let k = d.body["by_secret"].as_array().unwrap().iter().find(|x| x["secret"] == "K").unwrap();
    assert_eq!(k["actions"]["secret.read"], 3);
    assert_eq!(k["machines"], json!(["laptop", "server"]), "laptop created it, server read it");
    assert_eq!(k["actions"]["secret.create"], 1);
    assert!(d.body["totals"]["denied"].as_u64().unwrap() >= 1);
    assert!(
        d.body["by_machine"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["node"] == "friend-pc" && m["denied"] == 1)
    );
    assert!(
        d.body["latency"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l["key"] == "secret.read" && l["count"] == 3)
    );
    assert!(
        !d.body.to_string().contains("value-123456789"),
        "the dashboard never contains values"
    );

    let a = call(&app, LAPTOP, "GET", "/v1/audit/verify", &s.hdrs(), None).await;
    assert_eq!(a.body["ok"], true);
    app.db
        .raw()
        .execute("UPDATE events SET node = 'laptop' WHERE action = 'secret.read'", [])
        .unwrap();
    let a = call(&app, LAPTOP, "GET", "/v1/audit/verify", &s.hdrs(), None).await;
    assert_eq!(a.body["ok"], false, "editing the log breaks the chain");
}

async fn rpc(app: &AppRef, auth: &str, method: &str, params: Value) -> Resp {
    call(
        app,
        SPARK,
        "POST",
        "/mcp",
        &[("authorization", auth)],
        Some(json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })),
    )
    .await
}

fn tool_json(r: &Resp) -> Value {
    serde_json::from_str(r.body["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

#[tokio::test]
async fn mcp_exposes_metadata_and_proxy_but_never_values() {
    let app = test_app();
    let s = setup(&app).await;
    add(&app, &s, "OPENAI_API_KEY", &fake("sk-proj-", 'q', 36)).await;
    add(&app, &s, "NOTES_PW", "hunter2-hunter2").await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let claude = token(&app, &s, &["list", "proxy"], &["*"], &[]).await;

    assert_eq!(
        call(
            &app,
            SPARK,
            "POST",
            "/mcp",
            &[],
            Some(json!({"jsonrpc":"2.0","id":1,"method":"initialize"}))
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );

    let r = rpc(
        &app,
        &claude,
        "initialize",
        json!({ "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"} }),
    )
    .await;
    assert_eq!(r.body["result"]["protocolVersion"], "2025-06-18");
    let n = call(
        &app,
        SPARK,
        "POST",
        "/mcp",
        &[("authorization", &claude)],
        Some(json!({"jsonrpc":"2.0","method":"notifications/initialized"})),
    )
    .await;
    assert_eq!(n.status, StatusCode::ACCEPTED);

    let r = rpc(&app, &claude, "tools/list", json!({})).await;
    let names: Vec<_> = r.body["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["list_secrets", "describe_secret", "proxy_request"]);

    let r = rpc(&app, &claude, "tools/call", json!({ "name": "list_secrets", "arguments": {} })).await;
    let out = tool_json(&r);
    assert_eq!(out["secrets"].as_array().unwrap().len(), 2);
    let r = rpc(
        &app,
        &claude,
        "tools/call",
        json!({ "name": "describe_secret", "arguments": { "name": "OPENAI_API_KEY" } }),
    )
    .await;
    let out = tool_json(&r);
    assert_eq!(out["proxy"]["base_url"], "https://api.openai.com/");
    let all = format!(
        "{:?}",
        call(&app, LAPTOP, "GET", "/v1/events?limit=500", &s.hdrs(), None).await.body
    );
    assert!(!all.contains(&fake("sk-proj-", 'q', 36)), "events never contain values");

    let r = rpc(
        &app,
        &claude,
        "tools/call",
        json!({ "name": "proxy_request", "arguments": { "secret": "NOTES_PW", "path": "/x" } }),
    )
    .await;
    assert_eq!(r.body["result"]["isError"], true, "unknown provider has no proxy target");
    let r = rpc(
        &app,
        &claude,
        "tools/call",
        json!({ "name": "proxy_request", "arguments": { "secret": "OPENAI_API_KEY", "path": "../../etc" } }),
    )
    .await;
    assert_eq!(r.body["result"]["isError"], true);
    let r = rpc(
        &app,
        &claude,
        "tools/call",
        json!({ "name": "get_value", "arguments": { "name": "OPENAI_API_KEY" } }),
    )
    .await;
    assert_eq!(r.body["result"]["isError"], true, "there is no value tool");
    let r = rpc(&app, &claude, "nope", json!({})).await;
    assert_eq!(r.body["error"]["code"], -32601);

    let lister = token(&app, &s, &["list"], &["*"], &[]).await;
    let r = rpc(&app, &lister, "tools/list", json!({})).await;
    assert_eq!(
        r.body["result"]["tools"].as_array().unwrap().len(),
        2,
        "no proxy tool without the proxy scope"
    );
}

#[tokio::test]
async fn sensitive_actions_need_a_recent_passphrase() {
    let app = test_app();
    let s = setup(&app).await;
    add(&app, &s, "K", "value-123456789").await;
    assert_eq!(
        call(&app, LAPTOP, "GET", "/v1/secrets/K/value", &s.hdrs(), None).await.status,
        StatusCode::OK
    );

    // An hour later (or an agent replaying a stolen cookie): metadata yes, values no.
    app.sessions.make_stale();
    assert_eq!(
        call(&app, LAPTOP, "GET", "/v1/secrets", &s.hdrs(), None).await.status,
        StatusCode::OK
    );
    for (m, path, body) in [
        ("GET", "/v1/secrets/K/value", None),
        ("DELETE", "/v1/secrets/K", None),
        ("POST", "/v1/tokens", Some(json!({ "name": "x", "scopes": ["read"] }))),
        (
            "PATCH",
            "/v1/secrets/K",
            Some(json!({ "proxy": { "base_url": "https://x.example" } })),
        ),
    ] {
        let r = call(&app, LAPTOP, m, path, &s.hdrs(), body).await;
        assert_eq!(r.status, StatusCode::PRECONDITION_REQUIRED, "{m} {path}");
    }
    let r = call(
        &app,
        LAPTOP,
        "POST",
        "/v1/session/confirm",
        &s.hdrs(),
        Some(json!({ "passphrase": "nope nope nope" })),
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::FORBIDDEN,
        "wrong passphrase isn't mistaken for a lost session"
    );
    let r = call(
        &app,
        LAPTOP,
        "POST",
        "/v1/session/confirm",
        &s.hdrs(),
        Some(json!({ "passphrase": PASS })),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        call(&app, LAPTOP, "GET", "/v1/secrets/K/value", &s.hdrs(), None).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn parallel_wrong_passphrases_cant_beat_the_lockout() {
    let app = test_app();
    setup(&app).await;
    let mut tasks = vec![];
    for _ in 0..20 {
        let app = app.clone();
        tasks.push(tokio::spawn(async move {
            call(
                &app,
                SPARK,
                "POST",
                "/v1/session",
                &[],
                Some(json!({ "passphrase": "guess guess guess" })),
            )
            .await
            .status
        }));
    }
    let mut tried = 0;
    for t in tasks {
        if t.await.unwrap() == StatusCode::UNAUTHORIZED {
            tried += 1;
        }
    }
    assert!(tried <= 5, "{tried} guesses got through");
}

#[tokio::test]
async fn tokens_cant_hijack_the_describer_key_or_use_unsafe_methods() {
    let app = test_app();
    let s = setup(&app).await;
    add(&app, &s, "GITHUB_TOKEN", &fake("ghp_", 'a', 36)).await;
    let writer = token(&app, &s, &["write"], &["*"], &[]).await;
    let w = [("authorization", writer.as_str())];
    let mut app_cfg_with_claude = app.cfg.clone();
    app_cfg_with_claude.describe.claude_secret = Some("ANTHROPIC_API_KEY".into());
    // Use a fresh app sharing nothing but the config change.
    let app2 = Arc::new(App {
        cfg: app_cfg_with_claude,
        ..clone_app(&app)
    });
    let r = call(
        &app2,
        SPARK,
        "PATCH",
        "/v1/secrets/GITHUB_TOKEN",
        &w,
        Some(json!({ "name": "ANTHROPIC_API_KEY" })),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = call(
        &app2,
        SPARK,
        "POST",
        "/v1/secrets",
        &w,
        Some(json!({ "name": "ANTHROPIC_API_KEY", "value": "x-12345678" })),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    let r = call(
        &app,
        LAPTOP,
        "POST",
        "/v1/tokens",
        &s.hdrs(),
        Some(json!({ "name": "agent", "scopes": ["proxy"], "proxy_get_only": true })),
    )
    .await;
    let agent = format!("Bearer {}", r.body["token"].as_str().unwrap());
    let r = rpc(
        &app,
        &agent,
        "tools/call",
        json!({ "name": "proxy_request", "arguments": { "secret": "GITHUB_TOKEN", "method": "POST", "path": "/user/keys" } }),
    )
    .await;
    assert_eq!(r.body["result"]["isError"], true);
    assert!(tool_json(&r)["error"].as_str().unwrap().contains("GET"));
    let r = call(
        &app,
        SPARK,
        "POST",
        "/v1/proxy/GITHUB_TOKEN/user/keys",
        &[("authorization", agent.as_str())],
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
    let r = call(&app, LAPTOP, "TRACE", "/v1/proxy/GITHUB_TOKEN/x", &s.hdrs(), None).await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED, "TRACE would echo the injected key");
}

fn clone_app(a: &AppRef) -> App {
    App {
        cfg: a.cfg.clone(),
        db: a.db.clone(),
        vault: Vault::default(),
        sessions: Sessions::default(),
        limiter: LoginLimiter::default(),
        resolver: match &a.resolver {
            Resolver::Fixed(m) => Resolver::Fixed(m.clone()),
            _ => unreachable!(),
        },
        http: a.http.clone(),
        kdf: a.kdf,
        kdf_gate: Semaphore::new(2),
        origin: a.origin.clone(),
        denied_budget: Default::default(),
        imports: Default::default(),
        describe_gate: Semaphore::new(4),
        minted: Default::default(),
        endpoints: Default::default(),
        auto_unlock: Default::default(),
        stations: Default::default(),
    }
}

async fn add_with(app: &AppRef, s: &Session, body: Value) -> Resp {
    let mut body = body;
    body["verify"] = json!(false);
    call(app, LAPTOP, "POST", "/v1/secrets", &s.hdrs(), Some(body)).await
}

#[tokio::test]
async fn owner_only_secrets_are_invisible_to_every_token() {
    let app = test_app();
    let s = setup(&app).await;
    let wallet = format!("0x{}", "ab".repeat(32));
    let r = add_with(&app, &s, json!({ "name": "WALLET", "value": wallet })).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["owner_only"], true, "wallet keys start owner-only");
    assert_eq!(r.body["kind"], "private_key");
    assert_eq!(r.body["rotation"]["mode"], "never");
    let r = add_with(
        &app,
        &s,
        json!({ "name": "VPS_ROOT", "value": "hunter2 hunter2", "notes": "VPS root password" }),
    )
    .await;
    assert_eq!(r.body["owner_only"], true, "passwords start owner-only");
    assert_eq!(r.body["kind"], "password");
    add(&app, &s, "OPENAI_API_KEY", &fake("sk-proj-", 'q', 36)).await;

    let everything = token(&app, &s, &["list", "read", "write", "delete", "proxy"], &["*"], &[]).await;
    let h = [("authorization", everything.as_str())];
    let r = call(&app, SPARK, "GET", "/v1/secrets", &h, None).await;
    let names: Vec<_> = r.body["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, vec!["OPENAI_API_KEY"]);
    for (m, path, body) in [
        ("GET", "/v1/secrets/WALLET", None),
        ("GET", "/v1/secrets/WALLET/value", None),
        ("PATCH", "/v1/secrets/WALLET", Some(json!({ "value": "0xdead" }))),
        ("DELETE", "/v1/secrets/VPS_ROOT", None),
        ("POST", "/v1/secrets/WALLET/describe", None),
        ("GET", "/v1/proxy/VPS_ROOT/x", None),
    ] {
        assert_eq!(
            call(&app, SPARK, m, path, &h, body).await.status,
            StatusCode::NOT_FOUND,
            "{m} {path}"
        );
    }
    let r = rpc(&app, &everything, "tools/call", json!({ "name": "list_secrets", "arguments": {} })).await;
    assert!(!tool_json(&r).to_string().contains("WALLET"));
    let r = rpc(
        &app,
        &everything,
        "tools/call",
        json!({ "name": "describe_secret", "arguments": { "name": "WALLET" } }),
    )
    .await;
    assert_eq!(r.body["result"]["isError"], true);

    // The same value stored openly doesn't reveal the owner-only copy.
    let r = call(
        &app,
        SPARK,
        "POST",
        "/v1/secrets",
        &h,
        Some(json!({ "name": "WALLET_COPY", "value": wallet, "verify": false })),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED);
    assert_eq!(r.body["duplicate_of"], Value::Null, "{:?}", r.body);
    assert_eq!(r.body["duplicates"], json!([]));
    let r = call(&app, SPARK, "GET", "/v1/secrets", &h, None).await;
    assert!(!r.body.to_string().contains("\"WALLET\""), "owner-only names never reach a token");
    let r = call(&app, LAPTOP, "GET", "/v1/secrets/WALLET_COPY", &s.hdrs(), None).await;
    assert_eq!(r.body["duplicates"], json!(["WALLET"]), "the owner still sees it");
    call(&app, LAPTOP, "DELETE", "/v1/secrets/WALLET_COPY", &s.hdrs(), None).await;

    // Tokens can't flip the flag or set other owner settings.
    let r = call(
        &app,
        SPARK,
        "PATCH",
        "/v1/secrets/OPENAI_API_KEY",
        &h,
        Some(json!({ "owner_only": false })),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = call(
        &app,
        SPARK,
        "POST",
        "/v1/secrets",
        &h,
        Some(json!({ "name": "X", "value": "v-12345678", "fields": { "email": "a@b" } })),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // The owner sees everything; exposing an owner-only secret needs a fresh passphrase.
    let r = call(&app, LAPTOP, "GET", "/v1/secrets/WALLET/value", &s.hdrs(), None).await;
    assert_eq!(r.body["value"], wallet);
    app.sessions.make_stale();
    let r = call(
        &app,
        LAPTOP,
        "PATCH",
        "/v1/secrets/WALLET",
        &s.hdrs(),
        Some(json!({ "owner_only": false })),
    )
    .await;
    assert_eq!(r.status, StatusCode::PRECONDITION_REQUIRED);
    let r = call(
        &app,
        LAPTOP,
        "PATCH",
        "/v1/secrets/WALLET",
        &s.hdrs(),
        Some(json!({ "notes": "cold storage" })),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "harmless edits don't need it");
}

#[tokio::test]
async fn linked_parts_fields_and_duplicates() {
    let app = test_app();
    let s = setup(&app).await;
    let secret = fake("", 'S', 44);
    let r = add_with(
        &app,
        &s,
        json!({ "name": "ALPACA", "value": secret, "notes": "Alpaca paper", "fields": { "key_id": "PKTEST123" },
                "extras": [{ "name": "webhook_secret", "value": "whsec-1234567890" }] }),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["fields"]["key_id"], "PKTEST123");
    assert_eq!(r.body["parts"], json!(["webhook_secret"]));
    assert!(
        !r.body.to_string().contains("whsec-1234567890"),
        "metadata never carries secret parts"
    );
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let r = call(&app, LAPTOP, "GET", "/v1/secrets/ALPACA", &s.hdrs(), None).await;
    assert_eq!(r.body["provider"], "alpaca-paper", "PK key IDs are paper trading");
    assert_eq!(r.body["risk"], "low");
    assert_eq!(r.body["proxy_ready"], true);

    let r = call(&app, LAPTOP, "GET", "/v1/secrets/ALPACA/value", &s.hdrs(), None).await;
    assert_eq!(r.body["value"], secret);
    assert_eq!(r.body["parts"]["webhook_secret"], "whsec-1234567890");
    assert_eq!(r.body["fields"]["key_id"], "PKTEST123");

    // Changing only a part keeps the value and makes a new version; "" removes a part.
    let r = call(
        &app,
        LAPTOP,
        "PATCH",
        "/v1/secrets/ALPACA",
        &s.hdrs(),
        Some(json!({ "extras": [{ "name": "webhook_secret", "value": "" }], "verify": false })),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["version"], 2);
    assert_eq!(r.body["parts"], json!([]));
    let r = call(&app, LAPTOP, "GET", "/v1/secrets/ALPACA/value", &s.hdrs(), None).await;
    assert_eq!(r.body["value"], secret);

    // The same value stored twice is flagged, without revealing it.
    let r = add_with(&app, &s, json!({ "name": "ALPACA_COPY", "value": secret })).await;
    assert_eq!(r.body["duplicate_of"], "ALPACA");
    let r = call(&app, LAPTOP, "GET", "/v1/secrets", &s.hdrs(), None).await;
    let a = r.body["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["name"] == "ALPACA")
        .unwrap();
    assert_eq!(a["duplicates"], json!(["ALPACA_COPY"]));

    // A key that can rotate itself still needs its details first.
    let r = add_with(&app, &s, json!({ "name": "AZ", "value": format!("abc8Q~{}", "y".repeat(34)) })).await;
    assert_eq!(r.body["rotation"]["mode"], "auto");
    assert_eq!(r.body["rotation"]["ready"], false);
    assert_eq!(
        r.body["rotation"]["missing"],
        json!(["Tenant (directory) ID", "Application (client) ID"])
    );

    // Bad input is refused.
    for bad in [
        json!({ "name": "B1", "value": "v-12345678", "extras": [{ "name": "Bad Name", "value": "x" }] }),
        json!({ "name": "B2", "value": "v-12345678", "fields": { "k": 5 } }),
        json!({ "name": "B3", "value": "v-12345678", "provider": "nope" }),
        json!({ "name": "B4", "value": "v-12345678", "kind": "nuclear" }),
        json!({ "name": "B5", "value": "v-12345678", "parent": "MISSING" }),
    ] {
        assert_eq!(add_with(&app, &s, bad.clone()).await.status, StatusCode::BAD_REQUEST, "{bad}");
    }
}

// ---------------------------------------------------------------- rotation, against a fake provider

mod fake {
    use axum::{
        Router,
        body::Bytes,
        extract::State,
        http::{HeaderMap, Method, StatusCode, Uri},
        response::{IntoResponse, Response},
    };
    use serde_json::{Value, json};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    pub struct Fake {
        pub calls: Vec<String>,
        /// OpenRouter keys: (hash, key).
        pub or_keys: Vec<(String, String)>,
        pub cf_valid: Vec<String>,
        pub azure_ok: Vec<String>,
        pub slack_n: u32,
        pub fail_create: bool,
        /// After a roll, the new Cloudflare value fails verification.
        pub cf_break_verify: bool,
        pub last_body: Value,
    }
    pub type FakeRef = Arc<Mutex<Fake>>;

    fn masked(k: &str) -> String {
        format!("{}...{}", &k[..12], &k[k.len() - 3..])
    }
    fn bearer(h: &HeaderMap) -> String {
        h.get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("")
            .to_string()
    }
    fn ok(v: Value) -> Response {
        axum::Json(v).into_response()
    }
    fn err(code: StatusCode, v: Value) -> Response {
        (code, axum::Json(v)).into_response()
    }
    fn form(body: &[u8]) -> Vec<(String, String)> {
        url::form_urlencoded::parse(body).into_owned().collect()
    }

    async fn handle(State(f): State<FakeRef>, method: Method, uri: Uri, h: HeaderMap, body: Bytes) -> Response {
        let mut f = f.lock().unwrap();
        let path = uri.path().to_string();
        let query = uri.query().unwrap_or("").to_string();
        f.calls.push(format!("{method} {path}"));
        f.last_body = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let m = method.as_str();
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        match (m, parts.as_slice()) {
            // OpenRouter
            ("GET", ["or", "key"]) => {
                // Any OpenRouter-shaped key is valid somewhere; the list
                // decides whether it's in this account.
                let b = bearer(&h);
                if b.starts_with("sk-or-v1-") && b.len() > 20 {
                    ok(json!({ "data": { "label": masked(&b) } }))
                } else {
                    err(StatusCode::UNAUTHORIZED, json!({ "error": { "message": "bad key" } }))
                }
            }
            ("GET", ["or", "keys"]) => {
                let data: Vec<Value> = f
                    .or_keys
                    .iter()
                    .map(|(hash, k)| json!({ "hash": hash, "label": masked(k) }))
                    .collect();
                ok(json!({ "data": data }))
            }
            ("GET", ["or", "keys", _]) => ok(json!({ "data": { "limit": 5, "limit_reset": "monthly" } })),
            ("POST", ["or", "keys"]) => {
                if f.fail_create {
                    return err(StatusCode::INTERNAL_SERVER_ERROR, json!({ "error": { "message": "boom" } }));
                }
                let k = format!("sk-or-v1-{}", "e".repeat(64));
                f.or_keys.push(("newhash".into(), k.clone()));
                ok(json!({ "key": k, "data": { "hash": "newhash" } }))
            }
            ("DELETE", ["or", "keys", hash]) => {
                let hash = hash.to_string();
                f.or_keys.retain(|k| k.0 != hash);
                ok(json!({ "deleted": true }))
            }
            // Cloudflare
            ("GET", ["cf", "user", "tokens", "verify"]) => {
                if f.cf_valid.contains(&bearer(&h)) {
                    ok(json!({ "success": true, "result": { "id": "tok123", "status": "active" } }))
                } else {
                    err(
                        StatusCode::UNAUTHORIZED,
                        json!({ "success": false, "errors": [{ "message": "Invalid API Token" }] }),
                    )
                }
            }
            ("PUT", ["cf", "user", "tokens", "tok123", "value"]) => {
                if !f.cf_valid.contains(&bearer(&h)) {
                    return err(
                        StatusCode::FORBIDDEN,
                        json!({ "success": false, "errors": [{ "message": "no permission" }] }),
                    );
                }
                let new = format!("cfut_{}", "R".repeat(44));
                f.cf_valid = if f.cf_break_verify { vec![] } else { vec![new.clone()] };
                ok(json!({ "success": true, "result": new }))
            }
            // Tailscale
            ("POST", ["ts", "oauth", "token"]) => {
                let fm = form(&body);
                if fm.iter().any(|(k, v)| k == "client_id" && v == "cid") {
                    ok(json!({ "access_token": "ts-access", "expires_in": 3600 }))
                } else {
                    err(StatusCode::UNAUTHORIZED, json!({ "message": "bad client" }))
                }
            }
            ("GET", ["ts", "tailnet", "-", "keys", "kOLD123"]) => ok(json!({
                "id": "kOLD123",
                "capabilities": { "devices": { "create": { "reusable": false, "ephemeral": false, "preauthorized": true, "tags": ["tag:fw"] } } }
            })),
            ("POST", ["ts", "tailnet", "-", "keys"]) => {
                ok(json!({ "key": format!("tskey-auth-kNEW456-{}", "z".repeat(30)), "id": "kNEW456" }))
            }
            ("DELETE", ["ts", "tailnet", "-", "keys", _]) => ok(json!({})),
            // Microsoft
            ("POST", ["ms", _, "oauth2", "v2.0", "token"]) => {
                let fm = form(&body);
                let secret = fm
                    .iter()
                    .find(|(k, _)| k == "client_secret")
                    .map(|x| x.1.clone())
                    .unwrap_or_default();
                if f.azure_ok.contains(&secret) {
                    ok(json!({ "access_token": format!("az-{}", &secret[..3]), "expires_in": 3599 }))
                } else {
                    err(
                        StatusCode::UNAUTHORIZED,
                        json!({ "error": "invalid_client", "error_description": "bad secret" }),
                    )
                }
            }
            (_, ["graph", app]) if app.starts_with("applications(appId=") => {
                if !bearer(&h).starts_with("az-") {
                    return err(StatusCode::UNAUTHORIZED, json!({}));
                }
                let creds: Vec<Value> = f
                    .azure_ok
                    .iter()
                    .map(|s| json!({ "keyId": format!("k-{}", &s[..3]), "hint": &s[..3] }))
                    .collect();
                ok(json!({ "id": "obj1", "passwordCredentials": creds }))
            }
            ("POST", ["graph", app, action]) if app.starts_with("applications(appId=") => match *action {
                "addPassword" => {
                    let new = format!("xyz7Q~{}", "N".repeat(34));
                    f.azure_ok.push(new.clone());
                    ok(json!({ "secretText": new, "keyId": "k-xyz", "hint": "xyz" }))
                }
                "removePassword" => {
                    let key_id = f.last_body["keyId"].as_str().unwrap_or("").to_string();
                    f.azure_ok.retain(|s| format!("k-{}", &s[..3]) != key_id);
                    StatusCode::NO_CONTENT.into_response()
                }
                _ => err(StatusCode::NOT_FOUND, json!({})),
            },
            // Google
            ("POST", ["gtoken"]) => {
                let fm = form(&body);
                let jwt = fm.iter().find(|(k, _)| k == "assertion").map(|x| x.1.clone()).unwrap_or_default();
                if jwt.split('.').count() == 3 {
                    ok(json!({ "access_token": "g-access" }))
                } else {
                    err(StatusCode::BAD_REQUEST, json!({}))
                }
            }
            ("GET", ["gkeys", "keys:lookupKey"]) if query.starts_with("keyString=") => {
                ok(json!({ "name": "projects/123/locations/global/keys/oldkey", "parent": "projects/123" }))
            }
            ("GET", ["gkeys", "projects", "123", "locations", "global", "keys", "oldkey"]) => {
                ok(json!({ "displayName": "Maps", "restrictions": { "apiTargets": [{ "service": "maps.googleapis.com" }] } }))
            }
            ("POST", ["gkeys", "projects", "123", "locations", "global", "keys"]) => ok(json!({ "name": "operations/op1", "done": false })),
            ("GET", ["gkeys", "operations", "op1"]) => ok(json!({
                "name": "operations/op1", "done": true,
                "response": { "keyString": format!("AIza{}", "N".repeat(35)), "name": "projects/123/locations/global/keys/newkey" }
            })),
            ("DELETE", ["gkeys", "projects", "123", "locations", "global", "keys", _]) => {
                ok(json!({ "name": "operations/op2", "done": true }))
            }
            // GitHub
            ("POST", ["gh", "app", "installations", "42", "access_tokens"]) => {
                if bearer(&h).split('.').count() != 3 {
                    return err(StatusCode::UNAUTHORIZED, json!({ "message": "bad JWT" }));
                }
                let exp = crate::timeutil::format_rfc3339(crate::db::now_ms() + 3_600_000);
                ok(json!({ "token": "ghs_mintedtoken", "expires_at": exp }))
            }
            // Slack
            ("POST", ["slack", "oauth.v2.access"]) => {
                if !h
                    .get("authorization")
                    .is_some_and(|v| v.to_str().unwrap_or("").starts_with("Basic "))
                {
                    return ok(json!({ "ok": false, "error": "invalid_client" }));
                }
                f.slack_n += 1;
                let n = f.slack_n;
                ok(
                    json!({ "ok": true, "access_token": format!("xoxe.xoxb-access{n}"), "refresh_token": format!("xoxe-1-refresh{n}{}", "r".repeat(20)), "expires_in": 43200 }),
                )
            }
            // Anthropic
            ("GET", ["an", "models"]) => ok(json!({ "data": [] })),
            ("GET", ["an", "organizations", "api_keys"]) => ok(json!({
                "data": [
                    { "id": "apikey_old", "partial_key_hint": "sk-ant-api03-OLD...oldA" },
                    { "id": "apikey_other", "partial_key_hint": "sk-ant-api03-ZZZ...zzzz" }
                ],
                "has_more": false
            })),
            ("POST", ["an", "organizations", "api_keys", _]) => ok(json!({ "status": f.last_body["status"] })),
            _ => err(
                StatusCode::NOT_FOUND,
                json!({ "error": { "message": format!("fake has no {m} {path}") } }),
            ),
        }
    }

    pub async fn start() -> (crate::rotate::Endpoints, FakeRef) {
        let state: FakeRef = Default::default();
        let app = Router::new().fallback(handle).with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let ep = crate::rotate::Endpoints {
            openrouter: format!("{base}/or"),
            cloudflare: format!("{base}/cf"),
            tailscale: format!("{base}/ts"),
            ms_login: format!("{base}/ms"),
            graph: format!("{base}/graph"),
            google_token: format!("{base}/gtoken"),
            google_apikeys: format!("{base}/gkeys"),
            github: format!("{base}/gh"),
            slack: format!("{base}/slack"),
            anthropic: format!("{base}/an"),
        };
        (ep, state)
    }
}

async fn value_of(app: &AppRef, s: &Session, name: &str) -> String {
    let r = call(app, LAPTOP, "GET", &format!("/v1/secrets/{name}/value"), &s.hdrs(), None).await;
    r.body["value"].as_str().unwrap_or_default().to_string()
}

async fn rotate(app: &AppRef, s: &Session, name: &str, body: Option<Value>) -> Resp {
    call(
        app,
        LAPTOP,
        "POST",
        &format!("/v1/secrets/{name}/rotate"),
        &s.hdrs(),
        Some(body.unwrap_or(json!({}))),
    )
    .await
}

/// Pretends the grace period is over and runs the scheduler once.
async fn end_grace(app: &AppRef) {
    app.db
        .raw()
        .execute("UPDATE rotations SET revoke_after = 0 WHERE state = 'grace'", [])
        .unwrap();
    crate::rotate::tick(app).await;
}

#[tokio::test]
async fn openrouter_keys_rotate_through_the_management_key() {
    let (ep, f) = fake::start().await;
    let app = test_app_with(ep);
    let s = setup(&app).await;
    let old = format!("sk-or-v1-{}", "a".repeat(64));
    f.lock().unwrap().or_keys = vec![
        ("oldhash".into(), old.clone()),
        ("other".into(), format!("sk-or-v1-{}", "b".repeat(64))),
    ];
    add_with(
        &app,
        &s,
        json!({ "name": "OPENROUTER_MANAGEMENT_KEY", "value": format!("sk-or-v1-{}", "m".repeat(64)) }),
    )
    .await;
    let r = add_with(&app, &s, json!({ "name": "OR_APP", "value": old })).await;
    assert_eq!(r.body["rotation"]["mode"], "auto");
    assert_eq!(r.body["rotation"]["ready"], false, "no manager yet");
    let r = rotate(&app, &s, "OR_APP", None).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    assert!(r.body["error"].as_str().unwrap().contains("manager"));

    let r = call(
        &app,
        LAPTOP,
        "PATCH",
        "/v1/secrets/OR_APP",
        &s.hdrs(),
        Some(json!({ "parent": "OPENROUTER_MANAGEMENT_KEY" })),
    )
    .await;
    assert_eq!(r.body["rotation"]["ready"], true);
    let r = rotate(&app, &s, "OR_APP", None).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["rotation"]["state"], "grace");
    assert_eq!(r.body["rotation"]["mode"], "auto");
    let new = format!("sk-or-v1-{}", "e".repeat(64));
    assert_eq!(value_of(&app, &s, "OR_APP").await, new);
    assert!(!r.body.to_string().contains(&new), "the API response never carries the value");
    {
        let f = f.lock().unwrap();
        assert!(f.calls.contains(&"POST /or/keys".to_string()));
        assert!(
            f.or_keys.iter().any(|k| k.0 == "oldhash"),
            "old key still works during the grace period"
        );
    }
    // A second rotation can't start while the first is in its grace period.
    assert_eq!(rotate(&app, &s, "OR_APP", None).await.status, StatusCode::CONFLICT);

    end_grace(&app).await;
    let f2 = f.lock().unwrap();
    assert!(
        !f2.or_keys.iter().any(|k| k.0 == "oldhash"),
        "old key revoked after the grace period"
    );
    assert!(f2.or_keys.iter().any(|k| k.0 == "other"), "other keys untouched");
    drop(f2);
    let rows = app.db.rotations_recent(None, 10).unwrap();
    assert_eq!(rows[0].state, "done");
    let meta = app.db.secret_get("OR_APP").unwrap().unwrap();
    assert!(
        app.db.version_ciphertext(meta.id, 1).unwrap().is_none(),
        "the old ciphertext is erased"
    );
    assert!(meta.rotated_at.is_some());
}

#[tokio::test]
async fn failed_rotation_keeps_the_old_key() {
    let (ep, f) = fake::start().await;
    let app = test_app_with(ep);
    let s = setup(&app).await;
    let old = format!("sk-or-v1-{}", "a".repeat(64));
    f.lock().unwrap().or_keys = vec![("oldhash".into(), old.clone())];
    f.lock().unwrap().fail_create = true;
    add_with(
        &app,
        &s,
        json!({ "name": "OPENROUTER_MANAGEMENT_KEY", "value": format!("sk-or-v1-{}", "m".repeat(64)) }),
    )
    .await;
    add_with(
        &app,
        &s,
        json!({ "name": "OR_APP", "value": old, "parent": "OPENROUTER_MANAGEMENT_KEY" }),
    )
    .await;
    let r = rotate(&app, &s, "OR_APP", None).await;
    assert_eq!(r.status, StatusCode::BAD_GATEWAY);
    assert!(r.body["error"].as_str().unwrap().contains("old key is still in use"));
    assert_eq!(value_of(&app, &s, "OR_APP").await, old);
    let a = call(&app, LAPTOP, "GET", "/v1/attention", &s.hdrs(), None).await;
    assert!(
        a.body["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["secret"] == "OR_APP" && i["reason"].as_str().unwrap().contains("failed"))
    );
}

#[tokio::test]
async fn cloudflare_tokens_roll_in_place() {
    let (ep, f) = fake::start().await;
    let app = test_app_with(ep);
    let s = setup(&app).await;
    let old = format!("cfut_{}", "Q".repeat(44));
    f.lock().unwrap().cf_valid = vec![old.clone()];
    let r = add_with(&app, &s, json!({ "name": "CF_DNS", "value": old })).await;
    assert_eq!(r.body["rotation"]["ready"], true, "a Cloudflare token can try to roll itself");
    let r = rotate(&app, &s, "CF_DNS", None).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["rotation"]["state"], "done", "rolling invalidates the old value at once");
    assert_eq!(value_of(&app, &s, "CF_DNS").await, format!("cfut_{}", "R".repeat(44)));
}

#[tokio::test]
async fn azure_client_secrets_rotate_themselves() {
    let (ep, f) = fake::start().await;
    let app = test_app_with(ep);
    let s = setup(&app).await;
    let old = format!("abc8Q~{}", "O".repeat(34));
    f.lock().unwrap().azure_ok = vec![old.clone()];
    let r = add_with(
        &app,
        &s,
        json!({ "name": "AZ_BOT", "value": old, "fields": { "tenant_id": "tenant-1", "client_id": "app-1" } }),
    )
    .await;
    assert_eq!(r.body["provider"], "azure-app-secret");
    let r = rotate(&app, &s, "AZ_BOT", None).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["rotation"]["state"], "grace");
    let new = value_of(&app, &s, "AZ_BOT").await;
    assert!(new.starts_with("xyz7Q~"));
    assert_eq!(f.lock().unwrap().azure_ok.len(), 2, "both secrets work during the grace period");
    end_grace(&app).await;
    assert_eq!(f.lock().unwrap().azure_ok, vec![new], "the old secret was removed from the app");
}

#[tokio::test]
async fn tailscale_auth_keys_are_replaced_with_the_same_tags() {
    let (ep, f) = fake::start().await;
    let app = test_app_with(ep);
    let s = setup(&app).await;
    add_with(
        &app,
        &s,
        json!({ "name": "TS_OAUTH", "value": format!("tskey-client-kc1-{}", "s".repeat(30)), "fields": { "client_id": "cid" } }),
    )
    .await;
    let r = add_with(
        &app,
        &s,
        json!({ "name": "TS_AUTHKEY", "value": format!("tskey-auth-kOLD123-{}", "o".repeat(30)), "parent": "TS_OAUTH" }),
    )
    .await;
    assert_eq!(r.body["rotation"]["ready"], true);
    let r = rotate(&app, &s, "TS_AUTHKEY", None).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert!(value_of(&app, &s, "TS_AUTHKEY").await.starts_with("tskey-auth-kNEW456-"));
    let body = f.lock().unwrap().last_body.clone();
    assert_eq!(
        body["capabilities"]["devices"]["create"]["tags"],
        json!(["tag:fw"]),
        "tags copied from the old key"
    );
    end_grace(&app).await;
    assert!(f.lock().unwrap().calls.contains(&"DELETE /ts/tailnet/-/keys/kOLD123".to_string()));
}

fn test_pem() -> String {
    use aws_lc_rs::encoding::AsDer;
    use base64::Engine;
    let kp = aws_lc_rs::signature::RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
    let body = base64::engine::general_purpose::STANDARD.encode(kp.as_der().unwrap().as_ref());
    // Generated per run, and the header assembled, so scanners have nothing to flag.
    let (begin, end) = ("-----BEGIN ", "-----END ");
    format!("{begin}PRIVATE KEY-----\n{body}\n{end}PRIVATE KEY-----\n")
}

#[tokio::test]
async fn google_api_keys_rotate_with_a_service_account_and_keep_restrictions() {
    let (ep, f) = fake::start().await;
    let app = test_app_with(ep);
    let s = setup(&app).await;
    let sa = json!({ "type": (["service", "account"].join("_")), "client_email": "rot@p.iam.gserviceaccount.com", "private_key": test_pem(), "private_key_id": "k1" });
    add_with(&app, &s, json!({ "name": "GCP_ROTATOR", "value": sa.to_string() })).await;
    let r = add_with(
        &app,
        &s,
        json!({ "name": "GOOGLE_API_KEY", "value": format!("AIza{}", "O".repeat(35)), "parent": "GCP_ROTATOR" }),
    )
    .await;
    assert_eq!(r.body["rotation"]["ready"], true);
    let r = rotate(&app, &s, "GOOGLE_API_KEY", None).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(value_of(&app, &s, "GOOGLE_API_KEY").await, format!("AIza{}", "N".repeat(35)));
    assert!(
        f.lock()
            .unwrap()
            .calls
            .contains(&"POST /gkeys/projects/123/locations/global/keys".to_string())
    );
    end_grace(&app).await;
    assert!(
        f.lock()
            .unwrap()
            .calls
            .contains(&"DELETE /gkeys/projects/123/locations/global/keys/oldkey".to_string())
    );
}

#[tokio::test]
async fn anthropic_guided_rotation_disables_the_old_key_with_an_admin_key() {
    let (ep, f) = fake::start().await;
    let app = test_app_with(ep);
    let s = setup(&app).await;
    let old = format!("sk-ant-api03-OLD{}oldA", "x".repeat(80));
    add_with(
        &app,
        &s,
        json!({ "name": "ADMIN", "value": format!("sk-ant-admin01-{}", "q".repeat(60)) }),
    )
    .await;
    let r = add_with(&app, &s, json!({ "name": "CLAUDE", "value": old, "parent": "ADMIN" })).await;
    assert_eq!(r.body["rotation"]["mode"], "guided");
    assert_eq!(r.body["rotation"]["revokes_old"], true);
    assert_eq!(
        rotate(&app, &s, "CLAUDE", None).await.status,
        StatusCode::BAD_REQUEST,
        "no API to create Anthropic keys"
    );
    let r = rotate(&app, &s, "CLAUDE", Some(json!({ "value": old }))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "same value");
    let new = format!("sk-ant-api03-NEW{}", "y".repeat(80));
    let r = rotate(&app, &s, "CLAUDE", Some(json!({ "value": new }))).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["rotation"]["state"], "grace");
    assert!(
        f.lock().unwrap().calls.contains(&"GET /an/models".to_string()),
        "the new key was checked first"
    );
    end_grace(&app).await;
    let f = f.lock().unwrap();
    assert!(f.calls.contains(&"POST /an/organizations/api_keys/apikey_old".to_string()));
    assert_eq!(f.last_body["status"], "inactive", "disabled (reversible), not deleted");
}

#[tokio::test]
async fn guided_rotation_without_an_api_waits_for_the_owner_and_can_roll_back() {
    let app = test_app();
    let s = setup(&app).await;
    add_with(&app, &s, json!({ "name": "NEXUS", "value": "nexus-old-1234567890" })).await;
    let r = rotate(&app, &s, "NEXUS", Some(json!({ "value": "nexus-new-1234567890" }))).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["rotation"]["state"], "manual_revoke");
    assert_eq!(value_of(&app, &s, "NEXUS").await, "nexus-new-1234567890");
    let id = r.body["rotation"]["id"].as_i64().unwrap();

    // Changed my mind: the old value comes back.
    let r = call(&app, LAPTOP, "POST", &format!("/v1/rotations/{id}/rollback"), &s.hdrs(), None).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["rotation"]["state"], "rolled_back");
    assert_eq!(value_of(&app, &s, "NEXUS").await, "nexus-old-1234567890");
    let d = call(&app, LAPTOP, "GET", "/v1/secrets", &s.hdrs(), None).await;
    assert_eq!(d.body["secrets"][0]["duplicates"], json!([]), "fingerprint restored with the value");

    let r = rotate(&app, &s, "NEXUS", Some(json!({ "value": "nexus-new-2234567890" }))).await;
    let id = r.body["rotation"]["id"].as_i64().unwrap();
    let a = call(&app, LAPTOP, "GET", "/v1/attention", &s.hdrs(), None).await;
    assert!(a.body["items"].as_array().unwrap().iter().any(|i| i["action"] == "done"));
    app.sessions.make_stale();
    let r = call(&app, LAPTOP, "POST", &format!("/v1/rotations/{id}/done"), &s.hdrs(), None).await;
    assert_eq!(
        r.status,
        StatusCode::PRECONDITION_REQUIRED,
        "erasing the old value needs a fresh passphrase"
    );
    call(
        &app,
        LAPTOP,
        "POST",
        "/v1/session/confirm",
        &s.hdrs(),
        Some(json!({ "passphrase": PASS })),
    )
    .await;
    let r = call(&app, LAPTOP, "POST", &format!("/v1/rotations/{id}/done"), &s.hdrs(), None).await;
    assert_eq!(r.body["rotation"]["state"], "done");
    let meta = app.db.secret_get("NEXUS").unwrap().unwrap();
    assert!(
        app.db.version_ciphertext(meta.id, 1).unwrap().is_none(),
        "old value erased once deleted by hand"
    );

    // Only the owner, with a fresh passphrase, can rotate.
    let tok = token(&app, &s, &["write", "read"], &["*"], &[]).await;
    assert_eq!(
        call(
            &app,
            SPARK,
            "POST",
            "/v1/secrets/NEXUS/rotate",
            &[("authorization", tok.as_str())],
            Some(json!({}))
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    app.sessions.make_stale();
    assert_eq!(
        rotate(&app, &s, "NEXUS", Some(json!({ "value": "x-1234567890" }))).await.status,
        StatusCode::PRECONDITION_REQUIRED
    );
}

#[tokio::test]
async fn minted_credentials_github_app_and_slack() {
    let (ep, f) = fake::start().await;
    let app = test_app_with(ep);
    let s = setup(&app).await;
    add_with(
        &app,
        &s,
        json!({ "name": "GH_APP", "value": test_pem(), "provider": "github-app", "fields": { "app_id": "999", "installation_id": "42" } }),
    )
    .await;
    let meta = app.db.secret_get("GH_APP").unwrap().unwrap();
    assert_eq!(meta.provider.as_deref(), Some("github-app"));
    let stored = app.reveal(&meta).unwrap();
    let m = crate::rotate::proxy_material(&app, &meta, &stored).await.unwrap();
    assert_eq!(m.value, "ghs_mintedtoken");
    let _ = crate::rotate::proxy_material(&app, &meta, &stored).await.unwrap();
    let mints = f.lock().unwrap().calls.iter().filter(|c| c.contains("access_tokens")).count();
    assert_eq!(mints, 1, "the minted token is reused until it nears expiry");

    let r = add_with(&app, &s, json!({ "name": "SLACK_BOT", "value": format!("xoxe-1-{}", "f".repeat(40)), "fields": { "client_id": "123.456" }, "extras": [{ "name": "client_secret", "value": "cs-1234567890" }] })).await;
    assert_eq!(r.body["rotation"]["mode"], "minted");
    let meta = app.db.secret_get("SLACK_BOT").unwrap().unwrap();
    let stored = app.reveal(&meta).unwrap();
    let m = crate::rotate::proxy_material(&app, &meta, &stored).await.unwrap();
    assert_eq!(m.value, "xoxe.xoxb-access1");
    let meta2 = app.db.secret_get("SLACK_BOT").unwrap().unwrap();
    assert_eq!(meta2.version, 2, "Slack's new refresh token was saved");
    let v = app.reveal(&meta2).unwrap();
    assert!(v.value.starts_with("xoxe-1-refresh1"));
    assert_eq!(v.get("client_secret"), Some("cs-1234567890"), "other parts kept");
    assert!(
        app.db.version_ciphertext(meta.id, 1).unwrap().is_none(),
        "the spent refresh token is erased"
    );
}

#[tokio::test]
async fn scheduler_rotates_due_keys() {
    let (ep, f) = fake::start().await;
    let app = test_app_with(ep);
    let s = setup(&app).await;
    let old = format!("cfut_{}", "Q".repeat(44));
    f.lock().unwrap().cf_valid = vec![old.clone()];
    add_with(&app, &s, json!({ "name": "CF_DNS", "value": old.clone(), "rotate_every_days": 30 })).await;
    crate::rotate::tick(&app).await;
    assert_eq!(value_of(&app, &s, "CF_DNS").await, old, "not due yet");
    app.db.raw().execute("UPDATE secrets SET created_at = 0", []).unwrap();
    crate::rotate::tick(&app).await;
    assert_ne!(value_of(&app, &s, "CF_DNS").await, old, "rotated once due");
    let rows = app.db.rotations_recent(None, 5).unwrap();
    assert_eq!(rows[0].actor, "agentvault (scheduler)");
    crate::rotate::tick(&app).await;
    assert_eq!(
        app.db.rotations_recent(None, 5).unwrap().len(),
        1,
        "and not again until the next due date"
    );
}

#[tokio::test]
async fn import_preview_and_commit() {
    let app = test_app();
    let s = setup(&app).await;
    let mgmt = format!("sk-or-v1-{}", "1".repeat(64));
    let agent = format!("sk-or-v1-{}", "2".repeat(64));
    let gh = format!("ghp_{}", "G".repeat(36));
    let text = [
        format!("Openrouter Management Key: {mgmt}"),
        format!("chatbot key: {agent}"),
        format!("Github - {gh}"),
        format!("Github again - {gh}"),
        "N8N API KEY -".into(),
        format!("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ{}.{}", "x".repeat(20), "s".repeat(43)),
        "VPS root password: Blue Kite 42 &; tree".into(),
        "Router cabin ssh".into(),
    ]
    .join("\n");
    // Tokens can't import.
    let tok = token(&app, &s, &["write"], &["*"], &[]).await;
    let r = call(
        &app,
        SPARK,
        "POST",
        "/v1/import/preview",
        &[("authorization", tok.as_str())],
        Some(json!({ "text": text })),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    let r = call(&app, LAPTOP, "POST", "/v1/import/preview", &s.hdrs(), Some(json!({ "text": text }))).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let out = r.body.to_string();
    for v in [&mgmt, &agent, &gh, "Blue Kite 42 &; tree"] {
        assert!(!out.contains(v), "preview must not contain values");
    }
    let items = r.body["items"].as_array().unwrap().clone();
    let names: Vec<_> = items.iter().map(|i| i["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        vec![
            "OPENROUTER_MANAGEMENT_KEY",
            "OPENROUTER_CHATBOT_API_KEY",
            "GITHUB_TOKEN",
            "GITHUB_AGAIN_TOKEN",
            "N8N_API_KEY",
            "VPS_ROOT_PASSWORD"
        ]
    );
    assert_eq!(items[1]["parent"], "OPENROUTER_MANAGEMENT_KEY");
    assert_eq!(items[3]["include"], false);
    assert_eq!(items[5]["owner_only"], true);
    assert_eq!(r.body["unmatched"][0]["text"], "Router cabin ssh");
    let import_id = r.body["import_id"].as_str().unwrap().to_string();

    let commit = json!({
        "import_id": import_id,
        "items": items.iter().map(|i| {
            let mut c = json!({ "id": i["id"], "include": i["include"], "name": i["name"], "parent": i["parent"] });
            if i["name"] == "N8N_API_KEY" { c["base_url"] = json!("https://n8n.example.com"); }
            if i["name"] == "GITHUB_TOKEN" { c["name"] = json!("GITHUB_DOCS_TOKEN"); c["notes"] = json!("web-app project"); }
            c
        }).collect::<Vec<_>>(),
    });
    // Committing needs a fresh passphrase.
    app.sessions.make_stale();
    let r = call(&app, LAPTOP, "POST", "/v1/import/commit", &s.hdrs(), Some(commit.clone())).await;
    assert_eq!(r.status, StatusCode::PRECONDITION_REQUIRED);
    call(
        &app,
        LAPTOP,
        "POST",
        "/v1/session/confirm",
        &s.hdrs(),
        Some(json!({ "passphrase": PASS })),
    )
    .await;
    // The import id is single-use (and bound to the device that made it).
    let r = call(&app, LAPTOP, "POST", "/v1/import/commit", &s.hdrs(), Some(commit.clone())).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["created"], 5);
    assert_eq!(r.body["failed"], 0);
    let again = call(&app, LAPTOP, "POST", "/v1/import/commit", &s.hdrs(), Some(commit)).await;
    assert_eq!(again.status, StatusCode::GONE, "an import can't be committed twice");

    assert_eq!(value_of(&app, &s, "GITHUB_DOCS_TOKEN").await, gh);
    assert_eq!(value_of(&app, &s, "VPS_ROOT_PASSWORD").await, "Blue Kite 42 &; tree");
    let m = app.db.secret_get("OPENROUTER_CHATBOT_API_KEY").unwrap().unwrap();
    assert_eq!(m.parent.as_deref(), Some("OPENROUTER_MANAGEMENT_KEY"));
    assert!(m.exposed.as_deref().unwrap().contains("plaintext file"));
    assert_eq!(m.tags, vec!["imported"]);
    let n8n = app.db.secret_get("N8N_API_KEY").unwrap().unwrap();
    assert_eq!(n8n.proxy_base_url.as_deref(), Some("https://n8n.example.com"));
    let docs = app.db.secret_get("GITHUB_DOCS_TOKEN").unwrap().unwrap();
    assert!(docs.notes.contains("web-app project"));
    assert!(app.db.secret_get("VPS_ROOT_PASSWORD").unwrap().unwrap().owner_only);
    let a = call(&app, LAPTOP, "GET", "/v1/attention", &s.hdrs(), None).await;
    let exposed = a.body["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["reason"].as_str().unwrap().contains("plaintext"))
        .count();
    assert_eq!(exposed, 5, "every imported key is flagged until replaced");
    // Replacing a value clears the flag.
    call(
        &app,
        LAPTOP,
        "PATCH",
        "/v1/secrets/GITHUB_DOCS_TOKEN",
        &s.hdrs(),
        Some(json!({ "value": format!("ghp_{}", "H".repeat(36)), "verify": false })),
    )
    .await;
    assert!(app.db.secret_get("GITHUB_DOCS_TOKEN").unwrap().unwrap().exposed.is_none());
    let ev = call(&app, LAPTOP, "GET", "/v1/events?limit=500", &s.hdrs(), None)
        .await
        .body
        .to_string();
    assert!(!ev.contains(&gh) && !ev.contains("Blue Kite"), "values never reach the log");
}

async fn or_setup(f: &fake::FakeRef, app: &AppRef, s: &Session, in_account: bool) -> String {
    let old = format!("sk-or-v1-{}", "a".repeat(64));
    if in_account {
        f.lock().unwrap().or_keys = vec![("oldhash".into(), old.clone())];
    }
    add_with(
        app,
        s,
        json!({ "name": "OPENROUTER_MANAGEMENT_KEY", "value": format!("sk-or-v1-{}", "m".repeat(64)) }),
    )
    .await;
    add_with(
        app,
        s,
        json!({ "name": "OR_APP", "value": old, "parent": "OPENROUTER_MANAGEMENT_KEY" }),
    )
    .await;
    old
}

#[tokio::test]
async fn managers_are_owner_only_and_must_be_the_right_kind() {
    let (ep, f) = fake::start().await;
    let app = test_app_with(ep);
    let s = setup(&app).await;
    or_setup(&f, &app, &s, true).await;
    let mgr = app.db.secret_get("OPENROUTER_MANAGEMENT_KEY").unwrap().unwrap();
    assert!(mgr.owner_only, "a key becomes owner-only when it's made a manager");

    // Tokens can't touch the manager, or change the value of a managed key.
    let tok = token(&app, &s, &["list", "write", "delete"], &["*"], &[]).await;
    let h = [("authorization", tok.as_str())];
    let r = call(
        &app,
        SPARK,
        "PATCH",
        "/v1/secrets/OPENROUTER_MANAGEMENT_KEY",
        &h,
        Some(json!({ "value": "sk-or-v1-attacker" })),
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(
        call(&app, SPARK, "DELETE", "/v1/secrets/OPENROUTER_MANAGEMENT_KEY", &h, None)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    let r = call(
        &app,
        SPARK,
        "PATCH",
        "/v1/secrets/OR_APP",
        &h,
        Some(json!({ "value": format!("sk-or-v1-{}", "z".repeat(64)) })),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "a token can't plant the key rotation will act on");
    let r = call(&app, SPARK, "GET", "/v1/secrets/OR_APP", &h, None).await;
    assert_eq!(r.body["parent"], Value::Null, "an owner-only manager isn't named to tokens");

    // A manager that lost owner-only, or is the wrong kind, is refused before anything is created.
    app.db
        .raw()
        .execute("UPDATE secrets SET owner_only = 0 WHERE name = 'OPENROUTER_MANAGEMENT_KEY'", [])
        .unwrap();
    let r = rotate(&app, &s, "OR_APP", None).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    assert!(r.body["error"].as_str().unwrap().contains("owner-only"));
    app.db.raw().execute("UPDATE secrets SET owner_only = 1, provider = 'github', provider_name = 'GitHub token' WHERE name = 'OPENROUTER_MANAGEMENT_KEY'", []).unwrap();
    assert_eq!(rotate(&app, &s, "OR_APP", None).await.status, StatusCode::BAD_REQUEST);
    let r = call(&app, LAPTOP, "GET", "/v1/secrets/OR_APP", &s.hdrs(), None).await;
    assert_eq!(r.body["rotation"]["ready"], false, "a wrong-kind manager isn't shown as ready");
    assert!(
        r.body["rotation"]["manager_problem"]
            .as_str()
            .unwrap()
            .contains("isn't an OpenRouter management key"),
        "{:?}",
        r.body["rotation"]
    );
    let a = call(&app, LAPTOP, "GET", "/v1/attention", &s.hdrs(), None).await;
    assert!(
        a.body["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["secret"] == "OR_APP" && i["reason"].as_str().unwrap().contains("can't rotate automatically"))
    );
    assert!(
        !f.lock().unwrap().calls.iter().any(|c| c.starts_with("POST")),
        "nothing was created at the provider"
    );
    let rows = app.db.rotations_recent(None, 5).unwrap();
    assert!(rows.iter().all(|r| r.state == "failed"), "failed rotations don't stay 'running'");
}

#[tokio::test]
async fn rotation_refuses_keys_the_manager_cant_find() {
    let (ep, f) = fake::start().await;
    let app = test_app_with(ep);
    let s = setup(&app).await;
    or_setup(&f, &app, &s, false).await;
    let r = rotate(&app, &s, "OR_APP", None).await;
    assert_eq!(r.status, StatusCode::BAD_GATEWAY);
    assert!(
        r.body["error"].as_str().unwrap().contains("management key's account"),
        "{:?}",
        r.body
    );
    assert!(
        !f.lock().unwrap().calls.contains(&"POST /or/keys".to_string()),
        "no key made in the wrong account"
    );

    add_with(
        &app,
        &s,
        json!({ "name": "TS_OAUTH", "value": format!("tskey-client-kc1-{}", "s".repeat(30)), "fields": { "client_id": "cid" } }),
    )
    .await;
    add_with(
        &app,
        &s,
        json!({ "name": "TS_KEY", "value": format!("tskey-auth-kMISSING9-{}", "o".repeat(30)), "parent": "TS_OAUTH" }),
    )
    .await;
    let r = rotate(&app, &s, "TS_KEY", None).await;
    assert_eq!(r.status, StatusCode::BAD_GATEWAY, "{:?}", r.body);
    assert!(!f.lock().unwrap().calls.contains(&"POST /ts/tailnet/-/keys".to_string()));
}

#[tokio::test]
async fn a_rolled_cloudflare_value_is_kept_even_if_its_check_fails() {
    let (ep, f) = fake::start().await;
    let app = test_app_with(ep);
    let s = setup(&app).await;
    let old = format!("cfut_{}", "Q".repeat(44));
    {
        let mut f = f.lock().unwrap();
        f.cf_valid = vec![old.clone()];
        f.cf_break_verify = true;
    }
    add_with(&app, &s, json!({ "name": "CF", "value": old })).await;
    let r = rotate(&app, &s, "CF", None).await;
    assert_eq!(r.status, StatusCode::BAD_GATEWAY);
    assert!(r.body["error"].as_str().unwrap().contains("new value is saved"), "{:?}", r.body);
    assert_eq!(
        value_of(&app, &s, "CF").await,
        format!("cfut_{}", "R".repeat(44)),
        "the only working value isn't thrown away"
    );
}

#[tokio::test]
async fn undo_and_revocation_never_hit_the_current_key() {
    let (ep, f) = fake::start().await;
    let app = test_app_with(ep);
    let s = setup(&app).await;
    let old = or_setup(&f, &app, &s, true).await;
    let r = rotate(&app, &s, "OR_APP", None).await;
    let id = r.body["rotation"]["id"].as_i64().unwrap();
    // A second rotation can't start, by hand either, while one is open.
    let r = rotate(&app, &s, "OR_APP", Some(json!({ "value": format!("sk-or-v1-{}", "c".repeat(64)) }))).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    // Undo, then the grace period "ends": the restored key must not be revoked.
    let r = call(&app, LAPTOP, "POST", &format!("/v1/rotations/{id}/rollback"), &s.hdrs(), None).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(value_of(&app, &s, "OR_APP").await, old);
    end_grace(&app).await;
    assert!(
        f.lock().unwrap().or_keys.iter().any(|k| k.0 == "oldhash"),
        "the restored key is still alive"
    );
    assert!(
        !f.lock().unwrap().or_keys.iter().any(|k| k.0 == "newhash"),
        "the key made by the undone rotation was revoked"
    );

    // If the value changed after a rotation, it can't be undone and the vault revokes nothing.
    f.lock().unwrap().or_keys = vec![("oldhash".into(), old.clone())];
    let r = rotate(&app, &s, "OR_APP", None).await;
    let id = r.body["rotation"]["id"].as_i64().unwrap();
    call(
        &app,
        LAPTOP,
        "PATCH",
        "/v1/secrets/OR_APP",
        &s.hdrs(),
        Some(json!({ "value": format!("sk-or-v1-{}", "d".repeat(64)), "verify": false })),
    )
    .await;
    let r = call(&app, LAPTOP, "POST", &format!("/v1/rotations/{id}/rollback"), &s.hdrs(), None).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    end_grace(&app).await;
    assert_eq!(app.db.rotation_get(id).unwrap().unwrap().state, "manual_revoke");
    assert!(
        f.lock().unwrap().or_keys.iter().any(|k| k.0 == "oldhash"),
        "nothing revoked when the key changed underneath"
    );
}

#[tokio::test]
async fn rejected_keys_record_the_providers_reason_without_the_key() {
    let (ep, _f) = fake::start().await;
    let base = test_app_with(ep);
    let mut cfg = base.cfg.clone();
    cfg.describe.verify_with_provider = true;
    let app = Arc::new(App {
        cfg,
        endpoints: base.endpoints.clone(),
        ..clone_app(&base)
    });
    let s = setup(&app).await;
    let bad = format!("cfut_{}", "B".repeat(44));
    let r = call(
        &app,
        LAPTOP,
        "POST",
        "/v1/secrets",
        &s.hdrs(),
        Some(json!({ "name": "CF", "value": bad, "verify": true })),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED);
    let mut v = Value::Null;
    for _ in 0..50 {
        let r = call(&app, LAPTOP, "GET", "/v1/secrets/CF", &s.hdrs(), None).await;
        if r.body["describe_status"] != "pending" {
            v = r.body["facts"]["verification"].clone();
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(v["status"], "rejected");
    assert_eq!(v["reason"], "Invalid API Token");
    assert!(!v.to_string().contains(&bad));
}

#[tokio::test]
async fn changing_the_passphrase_flags_automatic_unlock_as_out_of_date() {
    use crate::app::AutoUnlock;
    // The stored boot passphrase (what the systemd credential would hold).
    let dir = std::env::temp_dir().join(format!("keys-unlock-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("passphrase");
    std::fs::write(&file, format!("{PASS}\n")).unwrap();
    let base = test_app();
    let mut cfg = base.cfg.clone();
    cfg.unlock.passphrase_file = Some(file);
    let app = Arc::new(App { cfg, ..clone_app(&base) });
    let s = setup(&app).await;
    assert_eq!(call(&app, LAPTOP, "GET", "/v1/status", &[], None).await.body["auto_unlock"], "off");

    // Off: nothing to warn about.
    let new = "a brand new passphrase";
    let r = call(
        &app,
        LAPTOP,
        "POST",
        "/v1/passphrase",
        &s.hdrs(),
        Some(json!({ "current": PASS, "new": new })),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["auto_unlock_stale"], false);

    // On, and changed back to the stored passphrase: still fine.
    app.auto_unlock.set(AutoUnlock::ON);
    let r = call(
        &app,
        LAPTOP,
        "POST",
        "/v1/passphrase",
        &s.hdrs(),
        Some(json!({ "current": new, "new": PASS })),
    )
    .await;
    assert_eq!(r.body["auto_unlock_stale"], false);
    assert_eq!(call(&app, LAPTOP, "GET", "/v1/status", &[], None).await.body["auto_unlock"], "on");

    // On, and changed to something else: the next restart would stay locked.
    let r = call(
        &app,
        LAPTOP,
        "POST",
        "/v1/passphrase",
        &s.hdrs(),
        Some(json!({ "current": PASS, "new": new })),
    )
    .await;
    assert_eq!(r.body["auto_unlock_stale"], true);
    assert_eq!(
        call(&app, LAPTOP, "GET", "/v1/status", &[], None).await.body["auto_unlock"],
        "stale"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn tokens_can_be_edited_and_changes_apply_at_once() {
    let app = test_app();
    let s = setup(&app).await;
    add(&app, &s, "K", "value-123456789").await;
    add(&app, &s, "NO_TARGET", "plain-value-without-a-provider").await;
    let r = call(
        &app,
        LAPTOP,
        "POST",
        "/v1/tokens",
        &s.hdrs(),
        Some(json!({ "name": "agent", "scopes": ["list", "proxy"], "proxy_get_only": true })),
    )
    .await;
    let id = r.body["id"].as_i64().unwrap();
    let tok = format!("Bearer {}", r.body["token"].as_str().unwrap());
    let t = [("authorization", tok.as_str())];
    let path = format!("/v1/tokens/{id}");

    assert_eq!(
        call(&app, SPARK, "GET", "/v1/secrets/K/value", &t, None).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&app, SPARK, "POST", "/v1/proxy/NO_TARGET/x", &t, None).await.status,
        StatusCode::METHOD_NOT_ALLOWED
    );

    // Add read, allow changes through the proxy, rename it.
    let edit = json!({ "name": "agent v2", "scopes": ["list", "proxy", "read"], "secrets": ["*"], "nodes": [], "proxy_get_only": false });
    let r = call(&app, LAPTOP, "PATCH", &path, &s.hdrs(), Some(edit.clone())).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["token"]["name"], "agent v2");
    assert!(
        r.body["token"].get("hash").is_none() && r.body.get("token").is_some_and(|t| !t.is_string()),
        "never returns the token or its hash"
    );
    // Same token string, new powers, no restart or re-setup.
    let r = call(&app, SPARK, "GET", "/v1/secrets/K/value", &t, None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["value"], "value-123456789");
    let r = call(&app, SPARK, "POST", "/v1/proxy/NO_TARGET/x", &t, None).await;
    assert_ne!(r.status, StatusCode::METHOD_NOT_ALLOWED, "POST now passes the GET-only gate");

    // Narrow it again: limited to other keys and another machine.
    let narrow = json!({ "name": "agent v2", "scopes": ["list"], "secrets": ["OTHER_*"], "nodes": ["laptop"], "proxy_get_only": true });
    assert_eq!(
        call(&app, LAPTOP, "PATCH", &path, &s.hdrs(), Some(narrow)).await.status,
        StatusCode::OK
    );
    assert_eq!(
        call(&app, SPARK, "GET", "/v1/secrets/K/value", &t, None).await.status,
        StatusCode::FORBIDDEN
    );

    // The change is in the audit log, old -> new.
    let ev = call(&app, LAPTOP, "GET", "/v1/events?limit=50", &s.hdrs(), None).await;
    let upd: Vec<&Value> = ev.body["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "token.update")
        .collect();
    assert_eq!(upd.len(), 2);
    assert!(
        upd.iter().any(|e| e["detail"]
            .as_str()
            .unwrap()
            .contains("[list,proxy] keys * machines any GET-only -> [list,proxy,read]")),
        "{upd:?}"
    );

    // Bad input, stale passphrase, a token editing itself, revoked tokens.
    let bad = call(
        &app,
        LAPTOP,
        "PATCH",
        &path,
        &s.hdrs(),
        Some(json!({ "name": "x", "scopes": ["root"] })),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    let bad = call(&app, LAPTOP, "PATCH", &path, &s.hdrs(), Some(json!({ "name": "x", "scopes": [] }))).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    let writer = token(&app, &s, &["list", "proxy", "read", "write", "delete"], &["*"], &[]).await;
    let r = call(
        &app,
        SPARK,
        "PATCH",
        &path,
        &[("authorization", writer.as_str())],
        Some(edit.clone()),
    )
    .await;
    assert!(
        r.status == StatusCode::FORBIDDEN || r.status == StatusCode::UNAUTHORIZED,
        "tokens can't edit tokens: {}",
        r.status
    );
    app.sessions.make_stale();
    assert_eq!(
        call(&app, LAPTOP, "PATCH", &path, &s.hdrs(), Some(edit.clone())).await.status,
        StatusCode::PRECONDITION_REQUIRED
    );
    call(
        &app,
        LAPTOP,
        "POST",
        "/v1/session/confirm",
        &s.hdrs(),
        Some(json!({ "passphrase": PASS })),
    )
    .await;
    assert_eq!(call(&app, LAPTOP, "DELETE", &path, &s.hdrs(), None).await.status, StatusCode::OK);
    assert_eq!(
        call(&app, LAPTOP, "PATCH", &path, &s.hdrs(), Some(edit.clone())).await.status,
        StatusCode::NOT_FOUND,
        "revoked stays revoked"
    );
    assert_eq!(
        call(&app, LAPTOP, "PATCH", "/v1/tokens/9999", &s.hdrs(), Some(edit)).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&app, SPARK, "GET", "/v1/secrets", &t, None).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn attention_items_can_be_okd_until_the_situation_changes() {
    let app = test_app();
    let s = setup(&app).await;
    add(&app, &s, "K", "value-123456789").await;
    add(&app, &s, "OTHER", "other-value-12345").await;
    let soon = crate::db::now_ms() + 5 * 86_400_000;
    let r = call(
        &app,
        LAPTOP,
        "PATCH",
        "/v1/secrets/K",
        &s.hdrs(),
        Some(json!({ "exposed": "Was in a plaintext file", "expires_at": soon })),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    call(
        &app,
        LAPTOP,
        "PATCH",
        "/v1/secrets/OTHER",
        &s.hdrs(),
        Some(json!({ "exposed": "also leaked" })),
    )
    .await;
    let kinds = |b: &Value, list: &str, name: &str| -> Vec<String> {
        b[list]
            .as_array()
            .unwrap()
            .iter()
            .filter(|i| i["secret"] == name)
            .map(|i| i["kind"].as_str().unwrap().to_string())
            .collect()
    };
    let att = call(&app, LAPTOP, "GET", "/v1/attention", &s.hdrs(), None).await.body;
    assert_eq!(kinds(&att, "items", "K"), ["exposed", "expiring"]);

    // OK hides K's items (and only K's), and is logged.
    let r = call(
        &app,
        LAPTOP,
        "POST",
        "/v1/attention/dismiss",
        &s.hdrs(),
        Some(json!({ "secret": "K" })),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let att = call(&app, LAPTOP, "GET", "/v1/attention", &s.hdrs(), None).await.body;
    assert!(kinds(&att, "items", "K").is_empty());
    assert_eq!(kinds(&att, "dismissed", "K").len(), 2);
    assert_eq!(kinds(&att, "items", "OTHER"), ["exposed"]);
    let d = call(&app, LAPTOP, "GET", "/v1/dashboard?range=24h", &s.hdrs(), None).await.body;
    assert_eq!(d["attention"]["total"], 1, "the dashboard count leaves OK'd items out");
    let ev = call(&app, LAPTOP, "GET", "/v1/events?limit=20", &s.hdrs(), None).await.body;
    assert!(
        ev["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "attention.dismiss" && e["detail"] == "exposed,expiring")
    );

    // A different expiry date is a new situation: that item comes back, the other stays OK'd.
    let later = soon + 86_400_000;
    call(
        &app,
        LAPTOP,
        "PATCH",
        "/v1/secrets/K",
        &s.hdrs(),
        Some(json!({ "expires_at": later })),
    )
    .await;
    let att = call(&app, LAPTOP, "GET", "/v1/attention", &s.hdrs(), None).await.body;
    assert_eq!(kinds(&att, "items", "K"), ["expiring"]);
    assert_eq!(kinds(&att, "dismissed", "K"), ["exposed"]);

    // Restore brings everything back.
    let r = call(
        &app,
        LAPTOP,
        "POST",
        "/v1/attention/restore",
        &s.hdrs(),
        Some(json!({ "secret": "K" })),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let att = call(&app, LAPTOP, "GET", "/v1/attention", &s.hdrs(), None).await.body;
    assert_eq!(kinds(&att, "items", "K"), ["exposed", "expiring"]);
    assert!(kinds(&att, "dismissed", "K").is_empty());

    // OK'd as exposed, then flagged again on a new version: it's back.
    call(
        &app,
        LAPTOP,
        "POST",
        "/v1/attention/dismiss",
        &s.hdrs(),
        Some(json!({ "secret": "K" })),
    )
    .await;
    let r = call(
        &app,
        LAPTOP,
        "PATCH",
        "/v1/secrets/K",
        &s.hdrs(),
        Some(json!({ "value": "new-value-987654321" })),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    call(
        &app,
        LAPTOP,
        "PATCH",
        "/v1/secrets/K",
        &s.hdrs(),
        Some(json!({ "exposed": "leaked again" })),
    )
    .await;
    let att = call(&app, LAPTOP, "GET", "/v1/attention", &s.hdrs(), None).await.body;
    assert_eq!(kinds(&att, "items", "K"), ["exposed"], "a new version is a new situation");

    // Owner only; nothing to OK is a 404.
    let tok = token(&app, &s, &["list", "proxy", "read", "write", "delete"], &["*"], &[]).await;
    let r = call(
        &app,
        SPARK,
        "POST",
        "/v1/attention/dismiss",
        &[("authorization", tok.as_str())],
        Some(json!({ "secret": "OTHER" })),
    )
    .await;
    assert!(
        r.status == StatusCode::FORBIDDEN || r.status == StatusCode::UNAUTHORIZED,
        "{}",
        r.status
    );
    call(
        &app,
        LAPTOP,
        "PATCH",
        "/v1/secrets/OTHER",
        &s.hdrs(),
        Some(json!({ "exposed": "" })),
    )
    .await;
    let r = call(
        &app,
        LAPTOP,
        "POST",
        "/v1/attention/dismiss",
        &s.hdrs(),
        Some(json!({ "secret": "OTHER" })),
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

// ---- regression tests from the November security review ----

#[tokio::test]
async fn a_stale_owner_session_cant_drive_keys_or_test_guesses() {
    let app = test_app();
    let s = setup(&app).await;
    add(&app, &s, "OPENAI_API_KEY", &fake("sk-proj-", 'q', 36)).await;
    // An agent running as the owner has the cookie and the CSRF value, but
    // the passphrase was entered long ago.
    app.sessions.make_stale();
    let h = s.hdrs();
    let r = call(&app, LAPTOP, "GET", "/v1/proxy/OPENAI_API_KEY/v1/models", &h, None).await;
    assert_eq!(
        r.status,
        StatusCode::PRECONDITION_REQUIRED,
        "proxying as the owner needs the passphrase"
    );
    let r = call(
        &app,
        LAPTOP,
        "POST",
        "/mcp",
        &h,
        Some(json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": { "name": "proxy_request", "arguments": { "secret": "OPENAI_API_KEY", "path": "/v1/models" } } })),
    )
    .await;
    assert_eq!(r.body["result"]["isError"], true, "{:?}", r.body);
    assert!(tool_json(&r)["error"].as_str().unwrap().contains("passphrase"));
    for (m, path, body) in [
        ("POST", "/v1/import/preview", json!({ "text": "x password: guess1" })),
        (
            "POST",
            "/v1/secrets",
            json!({ "name": "GUESS", "value": "guess-number-one", "verify": false }),
        ),
        (
            "PATCH",
            "/v1/secrets/OPENAI_API_KEY",
            json!({ "name": "MOVED_INTO_A_TOKEN_PATTERN" }),
        ),
        (
            "PATCH",
            "/v1/secrets/OPENAI_API_KEY",
            json!({ "value": "guess-number-two", "verify": false }),
        ),
    ] {
        let r = call(&app, LAPTOP, m, path, &h, Some(body)).await;
        assert_eq!(r.status, StatusCode::PRECONDITION_REQUIRED, "{m} {path}: {:?}", r.body);
    }
    assert!(app.db.secret_get("GUESS").unwrap().is_none());
    assert!(app.db.secret_get("OPENAI_API_KEY").unwrap().is_some(), "not renamed");
    // Notes and tags stay easy to edit.
    let r = call(
        &app,
        LAPTOP,
        "PATCH",
        "/v1/secrets/OPENAI_API_KEY",
        &h,
        Some(json!({ "notes": "prod" })),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn secret_ids_are_never_reused() {
    let app = test_app();
    let s = setup(&app).await;
    add(&app, &s, "A", "value-aaaaaaaaaa").await;
    let a = app.db.secret_get("A").unwrap().unwrap().id;
    let r = call(&app, LAPTOP, "DELETE", "/v1/secrets/A", &s.hdrs(), None).await;
    assert_eq!(r.status, StatusCode::OK);
    add(&app, &s, "B", "value-bbbbbbbbbb").await;
    let b = app.db.secret_get("B").unwrap().unwrap().id;
    assert!(b > a, "a new secret must not inherit a deleted one's id ({a} -> {b})");
}

#[tokio::test]
async fn a_write_token_cant_change_where_a_key_is_sent() {
    let app = test_app();
    let s = setup(&app).await;
    // Cloudflare's plain 40-character tokens are recognised only by the hint word.
    let value = fake("", 'C', 40);
    let r = add_with(
        &app,
        &s,
        json!({ "name": "CF_DNS", "value": value, "notes": "Cloudflare DNS token" }),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let wait = |app: AppRef| async move {
        for _ in 0..50 {
            let m = app.db.secret_get("CF_DNS").unwrap().unwrap();
            if m.describe_status != "pending" {
                return m.provider;
            }
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        }
        panic!("describe didn't finish");
    };
    assert_eq!(wait(app.clone()).await.as_deref(), Some("cloudflare"));
    let tok = token(&app, &s, &["list", "write", "proxy"], &["CF_*"], &[]).await;
    let h = [("authorization", tok.as_str())];
    let r = call(&app, SPARK, "PATCH", "/v1/secrets/CF_DNS", &h, Some(json!({ "notes": "magic" }))).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = call(&app, SPARK, "POST", "/v1/secrets/CF_DNS/describe", &h, None).await;
    assert!(r.status.is_success(), "{:?}", r.body);
    assert_eq!(
        wait(app.clone()).await.as_deref(),
        Some("cloudflare"),
        "editing notes must not re-route the key"
    );
}

#[tokio::test]
async fn token_pinning_holds_to_the_device_not_just_its_name() {
    let base = test_app();
    // Another device that has taken the name "server".
    let mut peers: HashMap<_, _> = match &base.resolver {
        Resolver::Fixed(m) => m.clone(),
        _ => unreachable!(),
    };
    let (ip, mut impostor) = caller("100.64.0.9", "server", OWNER, &[]);
    impostor.node_id = "n-impostor".into();
    peers.insert(ip, impostor);
    let app = Arc::new(App {
        resolver: Resolver::Fixed(peers),
        ..clone_app(&base)
    });
    let s = setup(&app).await;
    add(&app, &s, "K", "value-123456789").await;
    let tok = token(&app, &s, &["list"], &["*"], &["server"]).await;
    let h = [("authorization", tok.as_str())];
    assert_eq!(
        call(&app, SPARK, "GET", "/v1/secrets", &h, None).await.status,
        StatusCode::OK,
        "first use pins it"
    );
    assert_eq!(
        call(&app, "100.64.0.9", "GET", "/v1/secrets", &h, None).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(call(&app, SPARK, "GET", "/v1/secrets", &h, None).await.status, StatusCode::OK);
    // Editing the token's machines resets the pin.
    let id = app.db.token_list().unwrap()[0].id;
    let edit = json!({ "name": "test", "scopes": ["list"], "secrets": ["*"], "nodes": ["server"] });
    assert_eq!(
        call(&app, LAPTOP, "PATCH", &format!("/v1/tokens/{id}"), &s.hdrs(), Some(edit))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        call(&app, "100.64.0.9", "GET", "/v1/secrets", &h, None).await.status,
        StatusCode::OK
    );
    assert_eq!(
        call(&app, SPARK, "GET", "/v1/secrets", &h, None).await.status,
        StatusCode::FORBIDDEN
    );
}

#[test]
fn import_labels_never_keep_a_password() {
    use crate::import::{mask_line, parse};
    let key = fake("sk-proj-", 'q', 40);
    for (label, secret) in [
        ("AWS console pass: Hunter2!", "Hunter2"),
        ("openai bob:Hunter2!", "Hunter2"),
        ("site user bob pass hunter2", "hunter2"),
        ("wifi pass correcthorse", "correcthorse"),
        ("Bank card pin 4821", "4821"),
        ("router pw: tr0ub4dor", "tr0ub4dor"),
    ] {
        assert!(!mask_line(label).contains(secret), "{label} -> {}", mask_line(label));
        let p = parse(&format!("{label} {key}"));
        let c = &p.candidates[0];
        let name = crate::import::suggest_name(c, c.provider());
        assert!(!name.to_lowercase().contains(&secret.to_lowercase()), "{label} -> name {name}");
    }
    // Ordinary labels survive.
    assert_eq!(mask_line("Router cabin ssh"), "Router cabin ssh");
    assert_eq!(mask_line("Website deploys, GitHub"), "Website deploys, GitHub");
}

// ---- spandeck stations: connect (phase 1), rotation (phase 2), reports (phase 3) ----

/// Opens a token request from the machine at `ip`: (request id, collect code).
async fn open_request(app: &AppRef, ip: &str, label: &str) -> (String, String) {
    let r = call(app, ip, "POST", "/v1/token-requests", &[], Some(json!({ "station": label }))).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert!(r.body["approve_url"].as_str().unwrap().contains("#/approve/"));
    (
        r.body["request_id"].as_str().unwrap().to_string(),
        r.body["collect_code"].as_str().unwrap().to_string(),
    )
}

async fn collect_req(app: &AppRef, ip: &str, id: &str, code: &str) -> Resp {
    call(
        app,
        ip,
        "GET",
        &format!("/v1/token-requests/{id}"),
        &[("x-collect-code", code)],
        None,
    )
    .await
}

/// Opens, approves and collects a station token for the machine at `ip`.
async fn connect_station(app: &AppRef, s: &Session, ip: &str, body: Value) -> String {
    let (id, code) = open_request(app, ip, "my station").await;
    let r = call(
        app,
        LAPTOP,
        "POST",
        &format!("/v1/token-requests/{id}/approve"),
        &s.hdrs(),
        Some(body),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = collect_req(app, ip, &id, &code).await;
    assert_eq!(r.body["status"], "approved", "{:?}", r.body);
    format!("Bearer {}", r.body["token"].as_str().unwrap())
}

#[tokio::test]
async fn stations_connect_with_the_owners_approval_only() {
    let app = test_app();
    let s = setup(&app).await;
    add(&app, &s, "OPENAI_API_KEY", &fake("sk-proj-", 'q', 40)).await;
    add(&app, &s, "GITHUB_TOKEN", &fake("ghp_", 'g', 36)).await;
    let r = add_with(&app, &s, json!({ "name": "BANK_PASSWORD", "value": "hunter2 hunter2" })).await;
    assert_eq!(r.body["owner_only"], true);

    // Status: anyone on the tailnet learns only what discovery needs.
    let st = call(&app, TAGGED, "GET", "/v1/status", &[], None).await.body;
    assert_eq!(st["service"], "agentvault");
    assert_eq!(st["sealed"], false);
    assert!(
        st.get("describer").is_none() && st.get("hostname").is_none() && st.get("origin").is_none(),
        "{st}"
    );
    let st = call(&app, LAPTOP, "GET", "/v1/status", &[], None).await.body;
    assert_eq!(st["service"], "agentvault");
    assert!(st.get("describer").is_some(), "the owner still gets the full status");

    // Only the owner's devices and tagged machines may ask.
    let r = call(&app, FRIEND, "POST", "/v1/token-requests", &[], Some(json!({ "station": "x" }))).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let (first, _) = open_request(&app, TAGGED, "build box").await;
    let (id, code) = open_request(&app, TAGGED, "build box").await;
    let (spark_id, spark_code) = open_request(&app, SPARK, "server").await;
    let list = call(&app, LAPTOP, "GET", "/v1/token-requests", &s.hdrs(), None).await.body;
    let ids: Vec<&str> = list["requests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert!(!ids.contains(&first.as_str()), "a new request replaces the machine's pending one");
    assert_eq!(ids.len(), 2);
    let tagged = list["requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == id.as_str())
        .unwrap();
    assert_eq!(tagged["node"], "ci-runner");
    assert_eq!(tagged["token_name"], "spandeck:ci-runner");

    // Nothing to collect yet; never from another machine or with the wrong code.
    assert_eq!(collect_req(&app, TAGGED, &id, &code).await.body["status"], "pending");
    assert_eq!(collect_req(&app, LAPTOP, &id, &code).await.status, StatusCode::FORBIDDEN);
    assert_eq!(collect_req(&app, TAGGED, &id, "wrong").await.status, StatusCode::FORBIDDEN);

    // Approval needs the owner session and a fresh passphrase.
    let some_token = token(&app, &s, &["list", "proxy", "read", "write", "delete"], &["*"], &[]).await;
    let r = call(
        &app,
        SPARK,
        "POST",
        &format!("/v1/token-requests/{id}/approve"),
        &[("authorization", some_token.as_str())],
        Some(json!({})),
    )
    .await;
    assert!(
        r.status == StatusCode::FORBIDDEN || r.status == StatusCode::UNAUTHORIZED,
        "{}",
        r.status
    );
    assert_eq!(
        call(
            &app,
            SPARK,
            "GET",
            "/v1/token-requests",
            &[("authorization", some_token.as_str())],
            None
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    app.sessions.make_stale();
    let approve = json!({ "secrets": ["OPENAI_*"] });
    let r = call(
        &app,
        LAPTOP,
        "POST",
        &format!("/v1/token-requests/{id}/approve"),
        &s.hdrs(),
        Some(approve.clone()),
    )
    .await;
    assert_eq!(r.status, StatusCode::PRECONDITION_REQUIRED);
    call(
        &app,
        LAPTOP,
        "POST",
        "/v1/session/confirm",
        &s.hdrs(),
        Some(json!({ "passphrase": PASS })),
    )
    .await;
    let r = call(
        &app,
        LAPTOP,
        "POST",
        &format!("/v1/token-requests/{id}/approve"),
        &s.hdrs(),
        Some(approve),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["token_name"], "spandeck:ci-runner");

    // Collected once, by that machine.
    let got = collect_req(&app, TAGGED, &id, &code).await.body;
    assert_eq!(got["status"], "approved");
    assert_eq!(got["scopes"], json!(["list", "proxy"]));
    assert_eq!(got["proxy_get_only"], true);
    let tok = format!("Bearer {}", got["token"].as_str().unwrap());
    assert_eq!(
        collect_req(&app, TAGGED, &id, &code).await.status,
        StatusCode::NOT_FOUND,
        "a second collect fails"
    );

    // The issued token: listed keys only, no raw values, no owner-only keys, GET only, this machine only.
    let h = [("authorization", tok.as_str())];
    let names: Vec<String> = call(&app, TAGGED, "GET", "/v1/secrets", &h, None).await.body["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, ["OPENAI_API_KEY"]);
    assert_eq!(
        call(&app, TAGGED, "GET", "/v1/secrets/OPENAI_API_KEY/value", &h, None).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&app, TAGGED, "GET", "/v1/secrets/BANK_PASSWORD", &h, None).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&app, TAGGED, "POST", "/v1/proxy/OPENAI_API_KEY/v1/x", &h, None).await.status,
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        call(&app, SPARK, "GET", "/v1/secrets", &h, None).await.status,
        StatusCode::FORBIDDEN,
        "pinned to its machine"
    );
    let me = call(&app, TAGGED, "GET", "/v1/tokens/self", &h, None).await.body;
    assert_eq!(me["name"], "spandeck:ci-runner");
    assert_eq!(me["rotation"]["every_hours"], Value::Null);

    // The pane label is recorded as reported, and never sent on (proxy unit tests check the stripping).
    call(
        &app,
        TAGGED,
        "GET",
        "/v1/proxy/OPENAI_API_KEY/v1/models",
        &[h[0], ("x-agentvault-actor", "api/dev@ci-runner")],
        None,
    )
    .await;
    let ev = call(&app, LAPTOP, "GET", "/v1/events?limit=100", &s.hdrs(), None).await.body;
    let events = ev["events"].as_array().unwrap();
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "proxy" && e["actor"].as_str().unwrap().contains("api/dev@ci-runner (reported)"))
    );
    for action in ["token_request.open", "token_request.approve", "token_request.collect"] {
        assert!(events.iter().any(|e| e["action"] == action), "{action} is in the audit log");
    }

    // Denied: the station is told, and gets nothing.
    let r = call(
        &app,
        LAPTOP,
        "POST",
        &format!("/v1/token-requests/{spark_id}/deny"),
        &s.hdrs(),
        Some(json!({})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(collect_req(&app, SPARK, &spark_id, &spark_code).await.body["status"], "denied");

    // Approving the same station again replaces its earlier token.
    let tok2 = connect_station(&app, &s, TAGGED, json!({})).await;
    assert_eq!(
        call(&app, TAGGED, "GET", "/v1/secrets", &h, None).await.status,
        StatusCode::UNAUTHORIZED,
        "old token revoked"
    );
    assert_eq!(
        call(&app, TAGGED, "GET", "/v1/secrets", &[("authorization", tok2.as_str())], None)
            .await
            .status,
        StatusCode::OK
    );

    // Expired: a pending request yields nothing; an approved one never collected is revoked.
    let (pid, pcode) = open_request(&app, SPARK, "server").await;
    let (aid, acode) = open_request(&app, TAGGED, "build box").await;
    call(
        &app,
        LAPTOP,
        "POST",
        &format!("/v1/token-requests/{aid}/approve"),
        &s.hdrs(),
        Some(json!({})),
    )
    .await;
    let issued = app
        .db
        .token_list()
        .unwrap()
        .into_iter()
        .find(|t| t.name == "spandeck:ci-runner" && t.revoked_at.is_none())
        .unwrap()
        .id;
    app.stations.expire_all();
    assert_eq!(collect_req(&app, SPARK, &pid, &pcode).await.status, StatusCode::GONE);
    assert_eq!(collect_req(&app, TAGGED, &aid, &acode).await.status, StatusCode::GONE);
    assert!(app.db.token_get(issued).unwrap().unwrap().revoked_at.is_some());
    let ev = call(&app, LAPTOP, "GET", "/v1/events?limit=200", &s.hdrs(), None).await.body;
    assert!(
        ev["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "token_request.expired")
    );

    // The approval page can't be framed by another site.
    let r = call(&app, LAPTOP, "GET", "/", &[], None).await;
    assert_eq!(r.headers["x-frame-options"], "DENY");
    assert!(
        r.headers["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
}

#[tokio::test]
async fn station_tokens_rotate_without_the_owner() {
    let app = test_app();
    let s = setup(&app).await;
    add(&app, &s, "OPENAI_API_KEY", &fake("sk-proj-", 'q', 40)).await;
    let t0 = connect_station(&app, &s, TAGGED, json!({})).await;
    let h0 = [("authorization", t0.as_str())];
    let id = app
        .db
        .token_list()
        .unwrap()
        .into_iter()
        .find(|t| t.revoked_at.is_none())
        .unwrap()
        .id;

    // The Control Deck's setting: 1 hour minimum, or never; logged.
    let set = |v: Value| json!({ "every_hours": v });
    assert_eq!(
        call(&app, TAGGED, "PUT", "/v1/tokens/self/rotation", &h0, Some(set(json!(0))))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(&app, TAGGED, "PUT", "/v1/tokens/self/rotation", &h0, Some(set(json!(24))))
            .await
            .status,
        StatusCode::OK
    );
    let me = call(&app, TAGGED, "GET", "/v1/tokens/self", &h0, None).await.body;
    assert_eq!(me["rotation"]["every_hours"], 24);
    assert!(me["rotation"]["due_at"].as_i64().unwrap() > crate::db::now_ms());
    let ev = call(&app, LAPTOP, "GET", "/v1/events?limit=50", &s.hdrs(), None).await.body;
    assert!(
        ev["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "token.rotation_setting" && e["detail"] == "never -> every 24 h")
    );

    // Swap: the old token works until the new one's first use.
    assert_eq!(
        call(&app, LAPTOP, "POST", "/v1/tokens/self/rotate", &h0, None).await.status,
        StatusCode::FORBIDDEN,
        "only from its own machine"
    );
    let t1 = format!(
        "Bearer {}",
        call(&app, TAGGED, "POST", "/v1/tokens/self/rotate", &h0, None).await.body["token"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        call(&app, TAGGED, "GET", "/v1/secrets", &h0, None).await.status,
        StatusCode::OK,
        "crash before saving: still working"
    );
    // A repeat swap with the old token discards the unused new one.
    let t2 = format!(
        "Bearer {}",
        call(&app, TAGGED, "POST", "/v1/tokens/self/rotate", &h0, None).await.body["token"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        call(&app, TAGGED, "GET", "/v1/secrets", &[("authorization", t1.as_str())], None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let h2 = [("authorization", t2.as_str())];
    assert_eq!(
        call(&app, TAGGED, "GET", "/v1/secrets", &h2, None).await.status,
        StatusCode::OK,
        "first use promotes it"
    );
    let r = call(&app, TAGGED, "GET", "/v1/secrets", &h0, None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.body["code"], "token_replaced", "a stale copy is refused with a clear reason");
    assert!(call(&app, TAGGED, "GET", "/v1/tokens/self", &h2, None).await.body["rotation"]["last_rotated_at"].is_i64());

    // An unused new token doesn't keep the old one alive past a day.
    let t3 = call(&app, TAGGED, "POST", "/v1/tokens/self/rotate", &h2, None).await.body["token"]
        .as_str()
        .unwrap()
        .to_string();
    app.db
        .raw()
        .execute(
            "UPDATE tokens SET next_issued_at = ?1 WHERE id = ?2",
            rusqlite::params![crate::db::now_ms() - 25 * 3_600_000, id],
        )
        .unwrap();
    let r = call(&app, TAGGED, "GET", "/v1/secrets", &h2, None).await;
    assert_eq!(r.body["code"], "token_rotated");
    let t3 = format!("Bearer {t3}");
    let h3 = [("authorization", t3.as_str())];
    assert_eq!(call(&app, TAGGED, "GET", "/v1/secrets", &h3, None).await.status, StatusCode::OK);

    // Overdue (a laptop asleep past its interval): only rotating is allowed, then it carries on.
    let old = crate::db::now_ms() - 30 * 3_600_000;
    app.db
        .raw()
        .execute(
            "UPDATE tokens SET created_at = ?1, last_rotated_at = ?1, rotation_changed_at = ?1 WHERE id = ?2",
            rusqlite::params![old, id],
        )
        .unwrap();
    let r = call(&app, TAGGED, "GET", "/v1/secrets", &h3, None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.body["code"], "token_overdue");
    let t4 = format!(
        "Bearer {}",
        call(&app, TAGGED, "POST", "/v1/tokens/self/rotate", &h3, None).await.body["token"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        call(&app, TAGGED, "GET", "/v1/secrets", &[("authorization", t4.as_str())], None)
            .await
            .status,
        StatusCode::OK
    );

    // Never-expire tokens are unaffected by all of this.
    let plain = token(&app, &s, &["list"], &["*"], &[]).await;
    app.db
        .raw()
        .execute("UPDATE tokens SET created_at = ?1 WHERE name = 'test'", rusqlite::params![old])
        .unwrap();
    assert_eq!(
        call(&app, SPARK, "GET", "/v1/secrets", &[("authorization", plain.as_str())], None)
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn exposure_reports_land_on_attention_without_revealing_a_match() {
    let app = test_app();
    let s = setup(&app).await;
    let leaked = fake("sk-proj-", 'L', 40);
    add(&app, &s, "OPENAI_API_KEY", &leaked).await;
    let r = add_with(&app, &s, json!({ "name": "BANK_PASSWORD", "value": "correct horse battery" })).await;
    assert_eq!(r.body["owner_only"], true);
    let tok = connect_station(&app, &s, TAGGED, json!({})).await;
    let h = [("authorization", tok.as_str())];

    let report = |v: &str| json!({ "value": v, "place": "a transcript" });
    let hit = call(&app, TAGGED, "POST", "/v1/attention/report", &h, Some(report(&leaked))).await;
    let miss = call(
        &app,
        TAGGED,
        "POST",
        "/v1/attention/report",
        &h,
        Some(report("not-a-stored-value-123")),
    )
    .await;
    let hidden = call(
        &app,
        TAGGED,
        "POST",
        "/v1/attention/report",
        &h,
        Some(report("correct horse battery")),
    )
    .await;
    for r in [&hit, &miss, &hidden] {
        assert_eq!(r.status, StatusCode::ACCEPTED);
        assert_eq!(r.body, json!({ "received": true }), "the same reply every time");
    }
    // The match is made after the reply; the owner sees it on Needs attention.
    let mut kinds = vec![];
    for _ in 0..50 {
        let a = call(&app, LAPTOP, "GET", "/v1/attention", &s.hdrs(), None).await.body;
        kinds = a["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|i| i["kind"] == "reported")
            .map(|i| i["secret"].as_str().unwrap().to_string())
            .collect();
        if kinds.len() == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    kinds.sort();
    assert_eq!(
        kinds,
        ["BANK_PASSWORD", "OPENAI_API_KEY"],
        "owner-only keys are matched too; only the owner sees it"
    );
    assert_eq!(
        call(&app, TAGGED, "GET", "/v1/attention", &h, None).await.status,
        StatusCode::FORBIDDEN
    );
    let listed = call(&app, TAGGED, "GET", "/v1/secrets/OPENAI_API_KEY", &h, None).await.body;
    assert!(
        !listed.to_string().contains("reported"),
        "a token can't see the result through the key either"
    );

    // Replacing the value clears it.
    let r = call(
        &app,
        LAPTOP,
        "PATCH",
        "/v1/secrets/OPENAI_API_KEY",
        &s.hdrs(),
        Some(json!({ "value": fake("sk-proj-", 'N', 40), "verify": false })),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let a = call(&app, LAPTOP, "GET", "/v1/attention", &s.hdrs(), None).await.body;
    assert!(
        !a["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["kind"] == "reported" && i["secret"] == "OPENAI_API_KEY")
    );
}

#[tokio::test]
async fn only_revoked_tokens_can_be_removed_from_the_list() {
    let app = test_app();
    let s = setup(&app).await;
    let mut ids = vec![];
    for name in ["a", "b", "c"] {
        let r = call(
            &app,
            LAPTOP,
            "POST",
            "/v1/tokens",
            &s.hdrs(),
            Some(json!({ "name": name, "scopes": ["list"] })),
        )
        .await;
        ids.push(r.body["id"].as_i64().unwrap());
    }
    let listed = |r: &Resp| {
        r.body["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };

    // An active token can't be removed, only revoked.
    let r = call(
        &app,
        LAPTOP,
        "POST",
        &format!("/v1/tokens/{}/remove", ids[0]),
        &s.hdrs(),
        Some(json!({})),
    )
    .await;
    assert_eq!(r.status, StatusCode::CONFLICT);

    for id in &ids[..2] {
        assert_eq!(
            call(&app, LAPTOP, "DELETE", &format!("/v1/tokens/{id}"), &s.hdrs(), None)
                .await
                .status,
            StatusCode::OK
        );
    }
    // Remove one revoked token.
    let r = call(
        &app,
        LAPTOP,
        "POST",
        &format!("/v1/tokens/{}/remove", ids[0]),
        &s.hdrs(),
        Some(json!({})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = call(&app, LAPTOP, "GET", "/v1/tokens", &s.hdrs(), None).await;
    let mut names = listed(&r);
    names.sort();
    assert_eq!(names, ["b", "c"]);

    // Remove all revoked: b goes, the active c stays.
    let r = call(&app, LAPTOP, "POST", "/v1/tokens/remove-revoked", &s.hdrs(), Some(json!({}))).await;
    assert_eq!(r.body["removed"], 1);
    let r = call(&app, LAPTOP, "GET", "/v1/tokens", &s.hdrs(), None).await;
    assert_eq!(listed(&r), ["c"]);

    // Owner only, and logged.
    let tok = call(
        &app,
        LAPTOP,
        "POST",
        "/v1/tokens",
        &s.hdrs(),
        Some(json!({ "name": "agent", "scopes": ["list", "proxy", "read"] })),
    )
    .await;
    let bearer = format!("Bearer {}", tok.body["token"].as_str().unwrap());
    let r = call(
        &app,
        SPARK,
        "POST",
        "/v1/tokens/remove-revoked",
        &[("authorization", bearer.as_str())],
        Some(json!({})),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let ev = call(&app, LAPTOP, "GET", "/v1/events?limit=50", &s.hdrs(), None).await;
    assert!(ev.body.to_string().contains("token.remove"));
}
