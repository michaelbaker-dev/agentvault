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
    // A partial reply could carry an echoed key in pieces too small to match.
    "range",
    "if-range",
    // These turn a GET into another method at many providers, which would
    // get round a GET-only token.
    "x-http-method-override",
    // spandeck's pane label is for the vault's own log only.
    "x-agentvault-actor",
    "x-http-method",
    "x-method-override",
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
        // x-agentvault-*: the vault's own headers (CSRF, actor label) stay here.
        if HOP_BY_HOP.contains(&name) || STRIP_REQUEST.contains(&name) || name.starts_with("sec-") || name.starts_with("x-agentvault-") {
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

/// A redirect's target for an agent to follow itself, unless it carries the
/// key. Download links (GitHub's CI logs, for example) are signed URLs that
/// need no key, so the agent fetches them directly with no credentials.
pub fn redirect_location(status: u16, upstream: &reqwest::header::HeaderMap, redactor: &Redactor) -> Option<String> {
    if !(300..400).contains(&status) {
        return None;
    }
    let v = upstream.get(reqwest::header::LOCATION)?;
    if redactor.contains(v.as_bytes()) {
        return None;
    }
    v.to_str().ok().map(str::to_string)
}

/// Addresses the vault never fetches a download link from: its own machine,
/// the tailnet (100.64.0.0/10, fd7a:115c:a1e0::/48), local networks and
/// other special ranges. A provider's redirect must not reach your machines.
pub fn private_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_broadcast()
                || v.is_multicast()
                || v.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // shared address space; Tailscale
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xfe) == 18) // benchmarking
                || o[0] >= 240
        }
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return private_ip(IpAddr::V4(v4));
            }
            let s = v.segments();
            v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local, Tailscale's included
                || (s[0] & 0xffc0) == 0xfe80 // link-local
                || (s[0] == 0x64 && s[1] == 0xff9b) // NAT64 maps to IPv4 anywhere
                || (s[0] == 0x2001 && s[1] == 0x0db8)
        }
    }
}

const MAX_DOWNLOAD_HOPS: usize = 3;

/// Fetches a download link a provider redirected a GET to (GitHub's CI logs,
/// for example): https only, public addresses only, with no key or other
/// credentials, and the connection pinned to the checked address so DNS can't
/// switch it to a private one in between.
pub async fn fetch_download(from: &Url, location: &str) -> Result<reqwest::Response, String> {
    let mut url = from.join(location).map_err(|_| "the redirect address is invalid".to_string())?;
    for _ in 0..MAX_DOWNLOAD_HOPS {
        if url.scheme() != "https" {
            return Err("the download link isn't https, so the vault won't follow it".into());
        }
        let Some(url::Host::Domain(host)) = url.host().map(|h| h.to_owned()) else {
            return Err("the download link has no host name, so the vault won't follow it".into());
        };
        let port = url.port_or_known_default().unwrap_or(443);
        let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|_| format!("couldn't look up {host}"))?
            .collect();
        let Some(&addr) = addrs.first() else {
            return Err(format!("couldn't look up {host}"));
        };
        if addrs.iter().any(|a| private_ip(a.ip())) {
            return Err(format!(
                "{host} is on a private network; the vault only follows download links to public servers"
            ));
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .resolve(&host, addr)
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(180))
            .user_agent(concat!("agentvault/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| format!("download failed: {e}"))?;
        let resp = client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| format!("download failed: {}", without_url(&e)))?;
        if resp.status().is_redirection()
            && let Some(next) = resp.headers().get(reqwest::header::LOCATION).and_then(|v| v.to_str().ok())
        {
            url = url.join(next).map_err(|_| "the redirect address is invalid".to_string())?;
            continue;
        }
        if compressed(resp.headers()) {
            return Err("the download came compressed, which the vault can't check for the key".into());
        }
        return Ok(resp);
    }
    Err("the download link redirected too many times".into())
}

/// A `Server-Timing` value splitting a proxied call's time between the vault
/// (checks, unlocking the key) and the provider (until its reply started).
pub fn server_timing(vault: Duration, provider: Duration) -> HeaderValue {
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    HeaderValue::from_str(&format!("agentvault;dur={:.1}, provider;dur={:.1}", ms(vault), ms(provider)))
        .unwrap_or_else(|_| HeaderValue::from_static("agentvault"))
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
    let resp = tokio::time::timeout(UPSTREAM_TIMEOUT, rb.send())
        .await
        .map_err(|_| "the provider didn't start its reply within 3 minutes".to_string())?
        .map_err(|e| format!("upstream request failed: {}", without_url(&e)))?;
    // We asked for an uncompressed reply; a compressed one couldn't be checked
    // for an echoed key, so it isn't passed on.
    if compressed(resp.headers()) {
        return Err("the provider sent a compressed reply, which the vault can't check for the key".into());
    }
    Ok((resp, start.elapsed()))
}

/// True if a reply's body is encoded (gzip, br...), so it can't be redacted.
fn compressed(h: &reqwest::header::HeaderMap) -> bool {
    h.get(reqwest::header::CONTENT_ENCODING)
        .is_some_and(|e| !e.as_bytes().eq_ignore_ascii_case(b"identity"))
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
        // RFC 3986 leaves - . _ ~ unencoded; NON_ALPHANUMERIC encodes them.
        const RFC3986: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
            .remove(b'-')
            .remove(b'.')
            .remove(b'_')
            .remove(b'~');
        for secret in secrets.iter().filter(|s| !s.is_empty()) {
            forms.extend([
                secret.as_bytes().to_vec(),
                b64.encode(secret).into_bytes(),
                b64.encode(format!("{secret}:")).into_bytes(),
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret).into_bytes(),
            ]);
            // Percent-encoded, both ways of choosing what to encode, in upper
            // and lower case hex.
            for set in [percent_encoding::NON_ALPHANUMERIC, RFC3986] {
                let enc = percent_encoding::utf8_percent_encode(secret, set).to_string();
                if enc != *secret {
                    forms.push(lower_hex(&enc).into_bytes());
                    forms.push(enc.into_bytes());
                }
            }
            // Base64 of the key wherever it sits in a longer string: for each of
            // the three alignments, the encoded characters that depend only on
            // the key (dropping the 4 at each end that mix in neighbours).
            for engine in [
                &base64::engine::general_purpose::STANDARD,
                &base64::engine::general_purpose::URL_SAFE,
            ] {
                for k in 0..3 {
                    let mut buf = vec![0u8; k];
                    buf.extend_from_slice(secret.as_bytes());
                    let enc = engine.encode(&buf);
                    let start = if k == 0 { 0 } else { 4 };
                    if enc.len() >= start + 4 + 8 {
                        forms.push(enc.as_bytes()[start..enc.len() - 4].to_vec());
                    }
                }
            }
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
    /// no partial form at the end is emitted early. Only a tail that could be
    /// the start of a key is held back, so a streamed event that ends
    /// normally goes out at once instead of waiting for the next chunk.
    fn safe_split(&self, buf: &[u8]) -> usize {
        let mut split = buf.len();
        for f in &self.forms {
            let first = f[0];
            for k in (1..f.len().min(buf.len() + 1)).rev() {
                let at = buf.len() - k;
                if at >= split {
                    break;
                }
                if buf[at] == first && buf[at..] == f[..k] {
                    split = at;
                    break;
                }
            }
        }
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
/// catch a key split across chunks. `idle` ends the reply with an error when
/// the provider sends nothing for that long; `None` (for event streams, which
/// stay open between events) waits as long as the caller does.
pub fn redact_stream<S>(upstream: S, r: Arc<Redactor>, idle: Option<Duration>) -> impl Stream<Item = Result<Bytes, std::io::Error>> + Send
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
                let next = match idle {
                    Some(d) => match tokio::time::timeout(d, up.next()).await {
                        Ok(n) => n,
                        Err(_) => {
                            // What's held back may be part of a key: dropped, not sent.
                            let e = std::io::Error::other("the provider sent nothing for too long");
                            return Some((Err(e), (up, Vec::new(), true)));
                        }
                    },
                    None => up.next().await,
                };
                match next {
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

/// True for a server-sent event stream, which stays open between events.
pub fn is_event_stream(h: &reqwest::header::HeaderMap) -> bool {
    h.get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("text/event-stream"))
}

/// How long a provider may take to start its reply, and to go quiet partway
/// through one that isn't an event stream.
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(180);

/// `%2F` -> `%2f`, leaving the rest alone.
fn lower_hex(enc: &str) -> String {
    let b = enc.as_bytes();
    let mut out = String::with_capacity(enc.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            out.push('%');
            out.push((b[i + 1] as char).to_ascii_lowercase());
            out.push((b[i + 2] as char).to_ascii_lowercase());
            i += 3;
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn server_timing_splits_vault_and_provider_time() {
        let v = server_timing(Duration::from_micros(2_345), Duration::from_millis(160));
        assert_eq!(v.to_str().unwrap(), "agentvault;dur=2.3, provider;dur=160.0");
    }

    #[test]
    fn download_links_never_reach_private_addresses() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "100.101.102.103", // a tailnet address
            "169.254.169.254",
            "0.0.0.0",
            "::1",
            "fd7a:115c:a1e0::1", // Tailscale IPv6
            "fe80::1",
            "::ffff:192.168.1.1",
            "64:ff9b::a00:1",
        ] {
            assert!(private_ip(ip.parse().unwrap()), "{ip} must be refused");
        }
        for ip in ["140.82.112.3", "20.60.40.4", "2606:4700::1111"] {
            assert!(!private_ip(ip.parse().unwrap()), "{ip} is public");
        }
    }

    #[tokio::test]
    async fn download_links_are_refused_unless_https_public_and_named() {
        let from = Url::parse("https://api.github.com/repos/o/r/actions/jobs/1/logs").unwrap();
        for (loc, why) in [
            ("http://example.com/log", "isn't https"),
            ("https://127.0.0.1/log", "no host name"),
            ("https://[::1]/log", "no host name"),
            ("https://localhost/log", "private network"),
        ] {
            let e = fetch_download(&from, loc).await.unwrap_err();
            assert!(e.contains(why), "{loc}: {e}");
        }
    }

    #[test]
    fn redirects_are_passed_on_without_the_key() {
        let fake_key = format!("sk-{}", "q".repeat(16));
        let red = Redactor::new(&[fake_key.as_str()]);
        let mut h = reqwest::header::HeaderMap::new();
        let signed = "https://results.blob.core.windows.net/logs/job.txt?sig=abc&se=2026";
        h.insert("location", signed.parse().unwrap());
        assert_eq!(redirect_location(302, &h, &red).as_deref(), Some(signed));
        assert_eq!(redirect_location(200, &h, &red), None, "only for redirects");
        h.insert("location", format!("https://x.example/cb?key={fake_key}").parse().unwrap());
        assert_eq!(redirect_location(302, &h, &red), None, "never one that carries the key");
        assert_eq!(redirect_location(302, &reqwest::header::HeaderMap::new(), &red), None);
    }

    #[test]
    fn review_hardening_headers_encodings_and_offsets() {
        // Partial replies and method overrides never reach the provider.
        let mut h = HeaderMap::new();
        for n in [
            "range",
            "if-range",
            "x-http-method-override",
            "x-http-method",
            "x-method-override",
            "x-agentvault-actor",
            "x-agentvault-csrf",
        ] {
            h.insert(HeaderName::from_static(n), HeaderValue::from_static("x"));
        }
        h.insert("accept", HeaderValue::from_static("application/json"));
        let out = forward_request_headers(&h, &Auth::Bearer);
        assert_eq!(out.len(), 1, "{out:?}");
        // Compressed replies are refused.
        let mut r = reqwest::header::HeaderMap::new();
        assert!(!compressed(&r));
        r.insert("content-encoding", "identity".parse().unwrap());
        assert!(!compressed(&r));
        r.insert("content-encoding", "gzip".parse().unwrap());
        assert!(compressed(&r));
        // Echoed keys are caught in more encodings.
        let key = "ab/cd+ef=gh-ij_kl.mn~op";
        let red = Redactor::new(&[key]);
        let b64 = base64::engine::general_purpose::STANDARD;
        for echoed in [
            "ab%2Fcd%2Bef%3Dgh-ij_kl.mn~op".to_string(),         // RFC 3986
            "ab%2fcd%2bef%3dgh%2dij%5fkl%2emn%7eop".to_string(), // lower-case hex
            b64.encode(format!("x{key}y")),                      // base64, offset 1
            b64.encode(format!("xy{key}z")),                     // base64, offset 2
            base64::engine::general_purpose::URL_SAFE.encode(format!("x{key}")),
        ] {
            assert!(red.contains(echoed.as_bytes()), "missed {echoed}");
        }
    }

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
        let out: Vec<u8> = redact_stream(futures_util::stream::iter(chunks), r, None)
            .map(|c| c.unwrap().to_vec())
            .collect::<Vec<_>>()
            .await
            .concat();
        assert_eq!(String::from_utf8(out).unwrap(), "start [REDACTED] middle [REDACTED] end");
    }

    /// The first item of a stream that stays open after `chunks`.
    async fn first_out(chunks: &[&str], r: Arc<Redactor>, idle: Option<Duration>) -> Option<Result<Bytes, std::io::Error>> {
        let items: Vec<reqwest::Result<Bytes>> = chunks.iter().map(|c| Ok(Bytes::copy_from_slice(c.as_bytes()))).collect();
        let up = futures_util::stream::iter(items).chain(futures_util::stream::pending());
        let mut s = Box::pin(redact_stream(up, r, idle));
        tokio::time::timeout(Duration::from_secs(2), s.next()).await.ok().flatten()
    }

    #[tokio::test]
    async fn streamed_events_go_out_without_waiting_for_the_next_chunk() {
        let secret = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let r = Arc::new(Redactor::new(&[secret]));
        // A whole event goes out at once, though the stream stays open.
        let out = first_out(&["data: {\"n\":1}\n\n"], r.clone(), None)
            .await
            .expect("event sent")
            .unwrap();
        assert_eq!(&out[..], b"data: {\"n\":1}\n\n");
        // A tail that could start the key is held back, and only that tail.
        let out = first_out(&["data: sk-ABC"], r.clone(), None).await.expect("sent").unwrap();
        assert_eq!(&out[..], b"data: ");
        // A key split across chunks is still caught.
        let items: Vec<reqwest::Result<Bytes>> = ["data: sk-ABCDEFG", "HIJKLMNOPQRSTUVWXYZ0123456789 done\n\n"]
            .iter()
            .map(|c| Ok(Bytes::copy_from_slice(c.as_bytes())))
            .collect();
        let out: Vec<u8> = redact_stream(futures_util::stream::iter(items), r, None)
            .map(|c| c.unwrap().to_vec())
            .collect::<Vec<_>>()
            .await
            .concat();
        assert_eq!(String::from_utf8(out).unwrap(), "data: [REDACTED] done\n\n");
    }

    #[tokio::test]
    async fn a_quiet_reply_ends_unless_it_is_an_event_stream() {
        let r = Arc::new(Redactor::new(&["sk-ABCDEFGHIJKLMNOP"]));
        let items: Vec<reqwest::Result<Bytes>> = vec![Ok(Bytes::from_static(b"{\"partial\": sk-ABC"))];
        let up = futures_util::stream::iter(items).chain(futures_util::stream::pending());
        let mut s = Box::pin(redact_stream(up, r.clone(), Some(Duration::from_millis(50))));
        assert_eq!(&s.next().await.unwrap().unwrap()[..], b"{\"partial\": ");
        // The held-back start of the key is dropped, not sent.
        assert!(s.next().await.unwrap().is_err());
        assert!(s.next().await.is_none());
        // With no idle limit the stream just waits.
        let items: Vec<reqwest::Result<Bytes>> = vec![Ok(Bytes::from_static(b"data: 1\n\n"))];
        let up = futures_util::stream::iter(items).chain(futures_util::stream::pending());
        let mut s = Box::pin(redact_stream(up, r, None));
        s.next().await.unwrap().unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(200), s.next()).await.is_err());
    }

    #[test]
    fn event_streams_are_recognised() {
        let mut h = reqwest::header::HeaderMap::new();
        assert!(!is_event_stream(&h));
        h.insert(reqwest::header::CONTENT_TYPE, "Text/Event-Stream; charset=utf-8".parse().unwrap());
        assert!(is_event_stream(&h));
        h.insert(reqwest::header::CONTENT_TYPE, "application/json".parse().unwrap());
        assert!(!is_event_stream(&h));
    }

    #[test]
    fn methods() {
        assert!(allowed_method(&Method::POST, false));
        assert!(!allowed_method(&Method::POST, true));
        assert!(!allowed_method(&Method::TRACE, false));
        assert!(!allowed_method(&Method::OPTIONS, false));
    }
}
