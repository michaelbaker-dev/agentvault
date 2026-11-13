//! Forwards a request to a provider with the key attached server-side, so the
//! caller (e.g. Claude) uses the key without ever seeing it.

use axum::http::{HeaderMap, HeaderName, HeaderValue, Method};
use base64::Engine;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use url::Url;

use crate::db::SecretMeta;
use crate::material::Material;
use crate::providers;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    /// `Authorization: Bearer <key>`
    Bearer,
    /// `<name>: <key>`
    Header(String),
    /// HTTP Basic with the key as username and an empty password.
    Basic,
    /// HTTP Basic with a named part (e.g. the account email) as username and
    /// the key as password.
    BasicWith(String),
    /// `?<param>=<key>`
    Query(String),
    /// Several headers built from templates such as `{key_id}` or
    /// `Token {value}`, for providers that need more than one part.
    Headers(Vec<(String, String)>),
}

/// The material a request is authenticated with: the decrypted parts plus
/// the secret's plaintext fields (client ID, email...).
pub struct Creds<'a> {
    pub material: &'a Material,
    pub fields: &'a serde_json::Value,
}

impl Creds<'_> {
    pub fn lookup(&self, name: &str) -> Option<&str> {
        self.material
            .get(name)
            .or_else(|| self.fields.get(name).and_then(serde_json::Value::as_str))
    }
}

fn valid_ref(n: &str) -> bool {
    n == "value" || crate::material::valid_part_name(n)
}

/// Checks a `{part}` template: balanced braces around valid part names.
fn valid_template(t: &str) -> bool {
    let mut rest = t;
    while let Some(open) = rest.find('{') {
        let Some(close) = rest[open..].find('}') else { return false };
        if !valid_ref(&rest[open + 1..open + close]) {
            return false;
        }
        rest = &rest[open + close + 1..];
    }
    !rest.contains('}') && !t.is_empty() && !t.chars().any(|c| c.is_control())
}

fn render(t: &str, c: &Creds<'_>) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = t;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let close = rest[open..].find('}').ok_or("bad template")? + open;
        let name = &rest[open + 1..close];
        out.push_str(c.lookup(name).ok_or_else(|| format!("this secret has no '{name}' part"))?);
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

impl Auth {
    /// Parses `bearer`, `basic`, `basic:<part>`, `header:<name>`,
    /// `query:<param>` or `headers:<Name>=<template>;<Name>=<template>`.
    pub fn parse(spec: &str) -> Option<Self> {
        let spec = spec.trim();
        match spec {
            "bearer" => Some(Self::Bearer),
            "basic" => Some(Self::Basic),
            _ => {
                if let Some(h) = spec.strip_prefix("header:") {
                    let h = h.trim().to_ascii_lowercase();
                    HeaderName::from_bytes(h.as_bytes()).ok()?;
                    Some(Self::Header(h))
                } else if let Some(q) = spec.strip_prefix("query:") {
                    let q = q.trim();
                    (!q.is_empty() && q.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
                        .then(|| Self::Query(q.to_string()))
                } else if let Some(u) = spec.strip_prefix("basic:") {
                    let u = u.trim();
                    (valid_ref(u) && u != "value").then(|| Self::BasicWith(u.to_string()))
                } else if let Some(list) = spec.strip_prefix("headers:") {
                    let mut out = vec![];
                    for item in list.split(';').map(str::trim).filter(|x| !x.is_empty()) {
                        let (name, tmpl) = item.split_once('=')?;
                        let name = name.trim().to_ascii_lowercase();
                        HeaderName::from_bytes(name.as_bytes()).ok()?;
                        let tmpl = tmpl.trim();
                        if !valid_template(tmpl) {
                            return None;
                        }
                        out.push((name, tmpl.to_string()));
                    }
                    (!out.is_empty() && out.len() <= 4).then_some(Self::Headers(out))
                } else {
                    None
                }
            }
        }
    }

    pub fn apply(&self, mut rb: reqwest::RequestBuilder, c: &Creds<'_>) -> Result<reqwest::RequestBuilder, String> {
        let key = c.material.value.as_str();
        match self {
            Auth::Bearer => rb = rb.bearer_auth(key),
            Auth::Header(h) => rb = rb.header(h.as_str(), key),
            Auth::Basic => {
                let enc = base64::engine::general_purpose::STANDARD.encode(format!("{key}:"));
                rb = rb.header("authorization", format!("Basic {enc}"));
            }
            Auth::BasicWith(user) => {
                let u = c.lookup(user).ok_or_else(|| format!("this secret has no '{user}' part"))?;
                let enc = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{key}"));
                rb = rb.header("authorization", format!("Basic {enc}"));
            }
            Auth::Query(p) => rb = rb.query(&[(p.as_str(), key)]),
            Auth::Headers(list) => {
                for (name, tmpl) in list {
                    rb = rb.header(name.as_str(), render(tmpl, c)?);
                }
            }
        }
        Ok(rb)
    }

    fn header_names(&self) -> Vec<&str> {
        match self {
            Auth::Bearer | Auth::Basic | Auth::BasicWith(_) => vec!["authorization"],
            Auth::Header(h) => vec![h],
            Auth::Query(_) => vec![],
            Auth::Headers(list) => list.iter().map(|(n, _)| n.as_str()).collect(),
        }
    }
}

pub struct Target {
    pub base: Url,
    pub auth: Auth,
}

/// Validates an owner-supplied proxy base URL.
pub fn validate_base_url(s: &str) -> Result<Url, String> {
    let u = Url::parse(s.trim()).map_err(|e| format!("invalid URL: {e}"))?;
    if u.scheme() != "https" {
        return Err("proxy base URL must use https".into());
    }
    if u.host_str().is_none() || !u.username().is_empty() || u.password().is_some() {
        return Err("proxy base URL needs a host and no credentials".into());
    }
    if u.query().is_some() || u.fragment().is_some() {
        return Err("proxy base URL can't have a query or fragment".into());
    }
    Ok(u)
}

/// Where requests for this secret go: the owner's override, else the provider default.
pub fn target_for(meta: &SecretMeta) -> Option<Target> {
    let provider = meta.provider.as_deref().and_then(providers::by_id);
    let base = meta.proxy_base_url.as_deref().or_else(|| provider.and_then(|p| p.api_base))?;
    let auth = meta
        .proxy_auth
        .as_deref()
        .or_else(|| provider.map(|p| p.api_auth))
        .unwrap_or("bearer");
    Some(Target {
        base: validate_base_url(base).ok()?,
        auth: Auth::parse(auth)?,
    })
}

fn percent_decode_lossy(s: &str) -> String {
    percent_encoding::percent_decode_str(s).decode_utf8_lossy().into_owned()
}

/// Joins a caller-supplied path onto the base URL without letting it escape
/// the base's host or path prefix.
pub fn build_url(base: &Url, path: &str, query: Option<&str>) -> Result<Url, String> {
    let path = path.trim_start_matches('/');
    let decoded = percent_decode_lossy(path);
    // `..;` and friends count as `..` on some servers (Tomcat, Spring).
    if decoded.split('/').any(|seg| seg.starts_with("..") || seg == ".")
        || decoded.contains('\\')
        || decoded.contains("//")
        || decoded.chars().any(|c| c.is_control())
        || path.contains('#')
        || path.contains('?')
    {
        return Err("path not allowed".into());
    }
    let prefix = base.path().trim_end_matches('/');
    let mut u = base.clone();
    u.set_path(&format!("{prefix}/{path}"));
    u.set_query(query.filter(|q| !q.is_empty()));
    if u.scheme() != base.scheme() || u.host_str() != base.host_str() || u.port() != base.port() {
        return Err("path escaped the target host".into());
    }
    if !(u.path() == prefix || u.path().starts_with(&format!("{prefix}/"))) {
        return Err("path escaped the target prefix".into());
    }
    Ok(u)
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Request headers never forwarded upstream: our own auth, cookies, browser
/// context, and anything that could carry another credential.
const STRIP_REQUEST: &[&str] = &[
    "host",
    // Ask for an uncompressed reply so the key can be redacted if echoed.
    "accept-encoding",
    "authorization",
    "cookie",
    "x-api-key",
    "private-token",
    "x-goog-api-key",
    "content-length",
    "origin",
    "referer",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    crate::auth::CSRF_HEADER,
];

pub fn forward_request_headers(incoming: &HeaderMap, auth: &Auth) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (k, v) in incoming {
        let name = k.as_str();
        if HOP_BY_HOP.contains(&name) || STRIP_REQUEST.contains(&name) || name.starts_with("sec-") {
            continue;
        }
        if auth.header_names().contains(&name) {
            continue;
        }
        out.append(k.clone(), v.clone());
    }
    out
}

/// Copies upstream response headers, dropping any that contain the key
/// (e.g. a redirect `Location` carrying `?key=...`).
pub fn response_headers(upstream: &reqwest::header::HeaderMap, redactor: &Redactor) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (k, v) in upstream {
        let name = k.as_str();
        if HOP_BY_HOP.contains(&name) || name == "set-cookie" || name == "content-length" || name == "alt-svc" {
            continue;
        }
        if redactor.contains(v.as_bytes()) {
            continue;
        }
        if let (Ok(n), Ok(val)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_bytes(v.as_bytes())) {
            out.append(n, val);
        }
    }
    out
}

/// Sends the request. Returns the upstream response and the time to its headers.
pub async fn send(
    http: &reqwest::Client,
    target: &Target,
    creds: &Creds<'_>,
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(reqwest::Response, Duration), String> {
    let m = reqwest::Method::from_bytes(method.as_str().as_bytes()).map_err(|_| "bad method".to_string())?;
    let mut rb = http.request(m, url);
    for (k, v) in &headers {
        rb = rb.header(k.as_str(), v.as_bytes());
    }
    if !body.is_empty() {
        rb = rb.body(body);
    }
    rb = target.auth.apply(rb, creds)?;
    let start = Instant::now();
    let resp = rb
        .send()
        .await
        .map_err(|e| format!("upstream request failed: {}", without_url(&e)))?;
    Ok((resp, start.elapsed()))
}

/// reqwest errors include the URL, which for query-style auth contains the key.
fn without_url(e: &reqwest::Error) -> String {
    let mut s = e.to_string();
    if let Some(u) = e.url() {
        s = s.replace(u.as_str(), "<upstream>");
    }
    s
}

/// The methods the proxy forwards. Notably not TRACE, which echoes request
/// headers (including the injected key) back.
pub fn allowed_method(m: &Method, get_only: bool) -> bool {
    if get_only {
        *m == Method::GET
    } else {
        matches!(*m, Method::GET | Method::POST | Method::PUT | Method::PATCH | Method::DELETE)
    }
}

const REDACTED: &[u8] = b"[REDACTED]";

/// Blanks out the key, in the encodings a provider might echo it in, from
/// anything the proxy returns.
pub struct Redactor {
    forms: Vec<Vec<u8>>,
    longest: usize,
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (from..=hay.len() - needle.len()).find(|&i| hay[i..].starts_with(needle))
}

impl Redactor {
    /// Covers every secret part of a credential.
    pub fn for_creds(c: &Creds<'_>, auth: &Auth) -> Self {
        let mut r = Self::new(&c.material.secrets());
        // A Basic header echoed back carries base64("user:key").
        if let Auth::BasicWith(user) = auth
            && let Some(u) = c.lookup(user)
        {
            let enc = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{}", c.material.value));
            r.forms.push(enc.into_bytes());
            r.longest = r.forms.iter().map(Vec::len).max().unwrap_or(0);
        }
        r
    }

    pub fn new(secrets: &[&str]) -> Self {
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut forms: Vec<Vec<u8>> = vec![];
        for secret in secrets.iter().filter(|s| !s.is_empty()) {
            forms.extend([
                secret.as_bytes().to_vec(),
                b64.encode(secret).into_bytes(),
                b64.encode(format!("{secret}:")).into_bytes(),
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret).into_bytes(),
                percent_encoding::utf8_percent_encode(secret, percent_encoding::NON_ALPHANUMERIC)
                    .to_string()
                    .into_bytes(),
            ]);
        }
        forms.retain(|f| f.len() >= 8);
        forms.sort();
        forms.dedup();
        let longest = forms.iter().map(Vec::len).max().unwrap_or(0);
        Self { forms, longest }
    }

    /// Adds more secrets to blank out (e.g. the stored key behind a minted token).
    pub fn extend(&mut self, secrets: &[&str]) {
        let more = Self::new(secrets);
        self.forms.extend(more.forms);
        self.forms.sort();
        self.forms.dedup();
        self.longest = self.forms.iter().map(Vec::len).max().unwrap_or(0);
    }

    pub fn contains(&self, data: &[u8]) -> bool {
        self.forms.iter().any(|f| find(data, f, 0).is_some())
    }

    pub fn redact(&self, data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        for f in &self.forms {
            let mut from = 0;
            while let Some(i) = find(&out, f, from) {
                out.splice(i..i + f.len(), REDACTED.iter().copied());
                from = i + REDACTED.len();
            }
        }
        out
    }

    #[cfg(test)]
    pub fn redact_str(&self, s: &str) -> String {
        String::from_utf8_lossy(&self.redact(s.as_bytes())).into_owned()
    }

    /// Where a buffer can be cut so that no key form straddles the cut and
    /// no partial form at the end is emitted early.
    fn safe_split(&self, buf: &[u8]) -> usize {
        let hold = self.longest.saturating_sub(1);
        let mut split = buf.len().saturating_sub(hold);
        for f in &self.forms {
            let mut from = 0;
            while let Some(i) = find(buf, f, from) {
                if i < split && i + f.len() > split {
                    split = i;
                }
                from = i + 1;
            }
        }
        split
    }
}

/// Redacts a streamed body chunk by chunk, holding back just enough bytes to
/// catch a key split across chunks.
pub fn redact_stream<S>(upstream: S, r: Arc<Redactor>) -> impl Stream<Item = Result<Bytes, std::io::Error>> + Send
where
    S: Stream<Item = reqwest::Result<Bytes>> + Send + Unpin + 'static,
{
    futures_util::stream::unfold((upstream, Vec::<u8>::new(), false), move |(mut up, mut carry, done)| {
        let r = r.clone();
        async move {
            if done {
                return None;
            }
            loop {
                match up.next().await {
                    Some(Ok(chunk)) => {
                        carry.extend_from_slice(&chunk);
                        let split = r.safe_split(&carry);
                        if split == 0 {
                            continue;
                        }
                        let rest = carry.split_off(split);
                        let out = r.redact(&carry);
                        return Some((Ok(Bytes::from(out)), (up, rest, false)));
                    }
                    Some(Err(e)) => return Some((Err(std::io::Error::other(e)), (up, Vec::new(), true))),
                    None => {
                        let out = r.redact(&carry);
                        return Some((Ok(Bytes::from(out)), (up, Vec::new(), true)));
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_specs() {
        assert_eq!(Auth::parse("bearer"), Some(Auth::Bearer));
        assert_eq!(Auth::parse("header:X-Api-Key"), Some(Auth::Header("x-api-key".into())));
        assert_eq!(Auth::parse("query:key"), Some(Auth::Query("key".into())));
        assert_eq!(Auth::parse("header:bad header"), None);
        assert_eq!(Auth::parse("query:a&b"), None);
        assert_eq!(Auth::parse("nope"), None);
        assert_eq!(Auth::parse("basic:email"), Some(Auth::BasicWith("email".into())));
        assert_eq!(Auth::parse("basic:value"), None);
        assert_eq!(
            Auth::parse("headers:APCA-API-KEY-ID={key_id}; APCA-API-SECRET-KEY={value}"),
            Some(Auth::Headers(vec![
                ("apca-api-key-id".into(), "{key_id}".into()),
                ("apca-api-secret-key".into(), "{value}".into())
            ]))
        );
        assert_eq!(Auth::parse("headers:x={Bad}"), None);
        assert_eq!(Auth::parse("headers:x={value"), None);
        assert_eq!(Auth::parse("headers:x=a}b"), None);
    }

    #[test]
    fn templates_render_parts_and_fields() {
        let mut m = Material::single("SECRET");
        m.set_extra("client_secret", "CS".into());
        let fields = serde_json::json!({ "key_id": "PKID", "email": "me@x" });
        let c = Creds {
            material: &m,
            fields: &fields,
        };
        assert_eq!(render("{key_id}", &c).unwrap(), "PKID");
        assert_eq!(render("Token {value}/{client_secret}", &c).unwrap(), "Token SECRET/CS");
        assert!(render("{missing}", &c).is_err());
        let rb = Auth::BasicWith("email".into())
            .apply(reqwest::Client::new().get("https://x.example"), &c)
            .unwrap();
        let req = rb.build().unwrap();
        let expect = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("me@x:SECRET"));
        assert_eq!(req.headers()["authorization"], expect.as_str());
    }

    #[test]
    fn url_building_stays_on_target() {
        let base = Url::parse("https://api.example.com/v4").unwrap();
        assert_eq!(
            build_url(&base, "/projects/1", Some("a=b")).unwrap().as_str(),
            "https://api.example.com/v4/projects/1?a=b"
        );
        for bad in [
            "../admin",
            "a/../../x",
            "%2e%2e/x",
            "a//b",
            "a\\b",
            "@evil.com/x",
            "a#frag",
            "a?x=1",
            "a/%2E/b",
        ] {
            let r = build_url(&base, bad, None);
            if let Ok(u) = &r {
                assert_eq!(u.host_str(), Some("api.example.com"), "{bad}");
                assert!(u.path().starts_with("/v4/"), "{bad}");
                assert!(!bad.contains(".."), "{bad} should have been rejected");
            }
        }
        assert!(build_url(&base, "../admin", None).is_err());
        assert!(build_url(&base, "%2e%2e/admin", None).is_err());
        assert!(build_url(&base, "a//b", None).is_err());
        assert!(build_url(&base, "..;/admin", None).is_err());
    }

    #[test]
    fn base_url_validation() {
        assert!(validate_base_url("https://api.x.com").is_ok());
        assert!(validate_base_url("http://api.x.com").is_err());
        assert!(validate_base_url("https://user:pw@api.x.com").is_err());
        assert!(validate_base_url("https://api.x.com/?k=1").is_err());
        assert!(validate_base_url("javascript:alert(1)").is_err());
    }

    #[test]
    fn strips_client_credentials() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer kt_mine".parse().unwrap());
        h.insert("cookie", "a=b".parse().unwrap());
        h.insert("x-agentvault-csrf", "c".parse().unwrap());
        h.insert("content-type", "application/json".parse().unwrap());
        h.insert("anthropic-version", "2023-06-01".parse().unwrap());
        h.insert("apca-api-key-id", "client-sent".parse().unwrap());
        let out = forward_request_headers(&h, &Auth::Header("x-api-key".into()));
        assert!(out.get("authorization").is_none());
        assert!(out.get("cookie").is_none());
        assert!(out.get("x-agentvault-csrf").is_none());
        assert!(out.get("content-type").is_some());
        assert!(out.get("anthropic-version").is_some());
        let two = Auth::parse("headers:APCA-API-KEY-ID={key_id};APCA-API-SECRET-KEY={value}").unwrap();
        assert!(
            forward_request_headers(&h, &two).get("apca-api-key-id").is_none(),
            "callers can't supply auth headers"
        );
    }

    #[test]
    fn redaction_covers_encodings() {
        let r = Redactor::new(&["sk-12345678", "second-secret-part"]);
        assert_eq!(r.redact_str("a second-secret-part b"), "a [REDACTED] b");
        assert_eq!(r.redact_str("echo sk-12345678 back"), "echo [REDACTED] back");
        let b64 = base64::engine::general_purpose::STANDARD.encode("sk-12345678:");
        assert!(!r.redact_str(&format!("Basic {b64}")).contains(&b64));
        assert!(r.contains(b"https://x/?key=sk-12345678"));
        assert!(!r.contains(b"nothing here"));
    }

    #[tokio::test]
    async fn stream_redaction_handles_split_keys() {
        let secret = "sk-ABCDEFGHIJKLMNOP";
        let r = Arc::new(Redactor::new(&[secret]));
        let body = format!("start {secret} middle {secret} end");
        // Split at every possible position into 3-byte chunks.
        let chunks: Vec<reqwest::Result<Bytes>> = body.as_bytes().chunks(3).map(|c| Ok(Bytes::copy_from_slice(c))).collect();
        let out: Vec<u8> = redact_stream(futures_util::stream::iter(chunks), r)
            .map(|c| c.unwrap().to_vec())
            .collect::<Vec<_>>()
            .await
            .concat();
        assert_eq!(String::from_utf8(out).unwrap(), "start [REDACTED] middle [REDACTED] end");
    }

    #[test]
    fn methods() {
        assert!(allowed_method(&Method::POST, false));
        assert!(!allowed_method(&Method::POST, true));
        assert!(!allowed_method(&Method::TRACE, false));
        assert!(!allowed_method(&Method::OPTIONS, false));
    }
}
