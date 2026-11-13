//! Turns a pasted key dump (a `.env` file, or free-form notes like
//! "Stripe live - sk_live_...") into proposed secrets for the owner to review.
//! Everything here is pure text processing; nothing leaves the process.

use regex::Regex;
use serde::Serialize;
use std::sync::LazyLock;

use crate::material::Material;
use crate::providers::{self, Provider};

pub const MAX_TEXT: usize = 1024 * 1024;
pub const MAX_ITEMS: usize = 500;

/// One proposed secret. `material` never leaves the server.
pub struct Candidate {
    pub line: usize,
    pub label: String,
    pub material: Material,
    pub fields: serde_json::Map<String, serde_json::Value>,
    /// Related lines (URLs, logins) that aren't secrets, kept as notes.
    pub notes: Vec<String>,
    /// Name given in the file itself (`NAME=value`).
    pub env_name: Option<String>,
}

/// A line that looked like a label but had no value next to it.
#[derive(Serialize)]
pub struct Unmatched {
    pub line: usize,
    pub text: String,
}

pub struct Parsed {
    pub candidates: Vec<Candidate>,
    pub unmatched: Vec<Unmatched>,
}

static ENV_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]{1,127})\s*=\s*(.*?)\s*$"#).expect("regex"));
static INLINE_ENV: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"\b([A-Z][A-Z0-9_]{1,127})=["']?([^\s"']{8,})["']?"#).expect("regex"));
static UUID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$").expect("regex"));
static EMAIL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$").expect("regex"));
static USER_HOST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_.\-]+@(\d{1,3}(\.\d{1,3}){3}|[A-Za-z0-9.\-]+)(:\d+)?$").expect("regex"));
/// "Bank password: hunter2 x" — everything after the separator is the
/// value, spaces and all.
static PASSWORD_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(.{0,60}?\b(password|passwd|pwd|passphrase|passcode|pin)\b[^:=]{0,20}?)\s*(?::|=|\s-\s)\s*(\S.*)$").expect("regex")
});
/// "gmail password correcthorse": a password word followed by one token.
static PASSWORD_TAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(.{0,60}?\b(password|passwd|pwd|passphrase|passcode)\b)\s+(\S{6,256})$").expect("regex"));
/// A credential word followed by a separator: what follows is masked.
static LABELLED_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(password|passwd|pwd|passphrase|passcode|pin|secret|token|key|keu|apikey)\b([^:=]{0,20}?)(\s*(?::|=|\s-\s)\s*)\S.*$")
        .expect("regex")
});
static URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^https?://\S+$").expect("regex"));
static GOOGLE_CLIENT_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com$").expect("regex"));

/// Whether a token is plausibly a secret value rather than a word, URL,
/// path, package name, email address or login.
fn secretish(t: &str) -> bool {
    if t.len() < 16 || URL.is_match(t) || EMAIL.is_match(t) || USER_HOST.is_match(t) {
        return false;
    }
    if t.starts_with(['/', '~', '@', '.']) || t.contains("://") {
        return false;
    }
    if providers::detect(t, "").is_some() {
        return true;
    }
    let digits = t.chars().filter(char::is_ascii_digit).count();
    let letters = t.chars().filter(char::is_ascii_alphabetic).count();
    // A long run of letters only (or with a few digits) is usually prose or an identifier.
    t.chars().all(|c| c.is_ascii_alphanumeric() || "-_.+/=~:!$%*#".contains(c))
        && letters > 0
        && (digits >= 2 || t.contains(['_', '-', '~', '.']) && digits >= 1 || t.len() >= 32)
}

/// A URL that is itself a credential: a password in it, or a secret-looking
/// path segment or query value (Slack webhooks, `?token=...`).
fn url_has_secret(u: &str) -> bool {
    let Ok(url) = url::Url::parse(u) else { return false };
    url.password().is_some_and(|p| !p.is_empty())
        || url
            .path_segments()
            .is_some_and(|mut segs| segs.any(|seg| seg.len() >= 16 && secretish(seg)))
        || url.query_pairs().any(|(k, v)| {
            v.len() >= 12
                && (secretish(&v)
                    || [
                        "key",
                        "token",
                        "secret",
                        "sig",
                        "signature",
                        "apikey",
                        "api_key",
                        "access_token",
                        "password",
                    ]
                    .contains(&k.to_lowercase().as_str()))
        })
}

fn trim_token(t: &str) -> &str {
    t.trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | ',' | ';' | '(' | ')' | '<' | '>' | '[' | ']'))
}

/// The label text left on a line once the values are removed.
fn label_of(line: &str, values: &[&str]) -> String {
    let mut s = line.to_string();
    for v in values {
        s = s.replace(v, " ");
    }
    let s = s.replace(['❯', '$', '"', '\'', '`'], " ");
    let s = s
        .trim()
        .trim_end_matches([':', '-', '=', '–', '—', ' '])
        .trim_start_matches([':', '-', '=', ' '])
        .trim();
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn is_heading(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty() && t.len() <= 80 && t.split_whitespace().count() <= 8 && !t.ends_with('.')
}

/// Masks anything secret-looking, for showing a line back to the owner:
/// whatever follows "password:", "key -" and the like, and long tokens.
pub fn mask_line(line: &str) -> String {
    let line = LABELLED_VALUE.replace(line, "$1$2$3‹hidden›");
    let mut after_credential_word = false;
    line.split_whitespace()
        .map(|w| {
            let t = trim_token(w);
            let lower = t.to_ascii_lowercase();
            let digits = t.chars().filter(char::is_ascii_digit).count();
            let letters = t.chars().filter(char::is_ascii_alphabetic).count();
            let hide = t.len() >= 8 && (secretish(t) || digits >= 3 || digits >= 2 && letters >= 2)
                // Anything long after "password", "token"... may be the value itself.
                || after_credential_word && t.len() >= 6 && t != "‹hidden›"
                || t.chars().any(|c| !c.is_ascii_alphanumeric() && !"-_.,:;'()&/?!‹›".contains(c)) && t.len() >= 6;
            if [
                "password",
                "passwd",
                "pwd",
                "passphrase",
                "passcode",
                "secret",
                "token",
                "key",
                "keu",
                "apikey",
                "login",
                "pin",
            ]
            .contains(&lower.as_str())
            {
                after_credential_word = true;
            }
            if hide && !t.contains('‹') {
                format!("‹{} chars›", t.len())
            } else {
                w.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn parse(text: &str) -> Parsed {
    let lines: Vec<&str> = text.lines().collect();
    let mut out: Vec<Candidate> = vec![];
    let mut unmatched = vec![];
    // The last label-only line, with the line number it was on.
    let mut pending: Option<(usize, String)> = None;
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let n = i + 1;
        let t = line.trim();
        i += 1;
        if t.is_empty() || t.starts_with('#') && !t.contains("-----BEGIN") {
            continue;
        }

        // Multi-line PEM block.
        if t.contains("-----BEGIN") && t.contains("PRIVATE KEY") {
            let start = t.find("-----BEGIN").unwrap_or(0);
            let mut block = vec![t[start..].to_string()];
            let before = label_of(&t[..start], &[]);
            while !block.last().is_some_and(|l| l.contains("-----END")) && i < lines.len() {
                block.push(lines[i].trim().to_string());
                i += 1;
            }
            let label = if before.is_empty() {
                pending.take().map(|p| p.1).unwrap_or_default()
            } else {
                before
            };
            out.push(Candidate::new(n, label, block.join("\n")));
            continue;
        }

        // Multi-line JSON (e.g. a Google service account file).
        if t.starts_with('{') && !t.ends_with('}') {
            let mut block = vec![t.to_string()];
            let mut depth = t.matches('{').count() as i64 - t.matches('}').count() as i64;
            while depth > 0 && i < lines.len() && block.len() < 200 {
                let l = lines[i];
                depth += l.matches('{').count() as i64 - l.matches('}').count() as i64;
                block.push(l.to_string());
                i += 1;
            }
            let joined = block.join("\n");
            if serde_json::from_str::<serde_json::Value>(&joined).is_ok_and(|v| v.get("private_key").is_some()) {
                let label = pending.take().map(|p| p.1).unwrap_or_else(|| "service account".into());
                out.push(Candidate::new(n, label, joined));
            }
            continue;
        }

        // "Something password: value", where the value may contain anything,
        // or "something password value" with a single word after it.
        if let Some(c) = PASSWORD_LINE.captures(t).or_else(|| PASSWORD_TAIL.captures(t)) {
            let value = c[3].trim().to_string();
            if !value.is_empty() && value.len() <= 256 {
                out.push(Candidate::new(n, label_of(&c[1], &[]), value));
                pending = None;
                continue;
            }
        }

        // KEY=value (.env style).
        if let Some(c) = ENV_LINE.captures(t) {
            let value = c[2].trim_matches(|ch| ch == '"' || ch == '\'').to_string();
            if !value.is_empty() {
                let mut cand = Candidate::new(n, c[1].replace('_', " "), value);
                cand.env_name = Some(c[1].to_string());
                out.push(cand);
                pending = None;
                continue;
            }
        }

        let tokens: Vec<&str> = t.split_whitespace().map(trim_token).collect();
        let mut values: Vec<String> = vec![];
        let mut env_names: Vec<Option<String>> = vec![];
        for c in INLINE_ENV.captures_iter(t) {
            if secretish(&c[2]) || c[2].len() >= 16 {
                values.push(c[2].to_string());
                env_names.push(Some(c[1].to_string()));
            }
        }
        for tok in &tokens {
            if URL.is_match(tok) && url_has_secret(tok) {
                values.push(tok.to_string());
                env_names.push(None);
                continue;
            }
            if secretish(tok) && !values.iter().any(|v| tok.contains(v.as_str())) {
                values.push(tok.to_string());
                env_names.push(None);
            }
        }
        let emails: Vec<&str> = tokens
            .iter()
            .copied()
            .filter(|x| EMAIL.is_match(x) && !USER_HOST.is_match(x) || EMAIL.is_match(x))
            .collect();
        let logins: Vec<&str> = tokens
            .iter()
            .copied()
            .filter(|x| USER_HOST.is_match(x) && !EMAIL.is_match(x))
            .collect();
        let urls: Vec<&str> = tokens.iter().copied().filter(|x| URL.is_match(x)).collect();

        if values.is_empty() {
            // Metadata for the previous secret: a login, or a URL right after it.
            if let Some(prev) = out.last_mut().filter(|p| n - p.line <= 3) {
                if let Some(l) = logins.first() {
                    prev.fields.insert("ssh_login".into(), serde_json::json!(l));
                    continue;
                }
                if let Some(u) = urls.first() {
                    // Only the site: a path or query can carry a token.
                    if let Ok(parsed) = url::Url::parse(u)
                        && let Some(host) = parsed.host_str()
                    {
                        prev.notes.push(format!("Related site: {}://{host}", parsed.scheme()));
                    }
                    continue;
                }
            }
            if urls.is_empty() && is_heading(t) {
                report(pending.replace((n, label_of(t, &[]))), &mut unmatched);
            }
            continue;
        }

        let vrefs: Vec<&str> = values.iter().map(String::as_str).collect();
        let mut drop_from_label: Vec<&str> = vrefs.clone();
        drop_from_label.extend(emails.iter().copied());
        let mut label = label_of(t, &drop_from_label);
        for (name, _) in env_names.iter().zip(&values) {
            if let Some(nm) = name {
                label = label.replace(&format!("{nm}="), " ");
            }
        }
        if label.chars().filter(char::is_ascii_alphabetic).count() < 2 {
            label = pending.take().map(|p| p.1).unwrap_or_default();
        }
        report(pending.take(), &mut unmatched);

        // A UUID next to another value is that value's ID. On its own it's
        // usually an ID too (a session or object ID), unless the label says key.
        let (ids, rest): (Vec<_>, Vec<_>) = values.iter().zip(env_names).partition(|(v, _)| UUID.is_match(v));
        let labelled_key = words(&label)
            .iter()
            .any(|w| ["key", "token", "secret", "password", "apikey"].contains(&w.as_str()));
        let rest = if rest.is_empty() && labelled_key { ids.clone() } else { rest };
        for (v, env) in rest {
            let mut c = Candidate::new(n, label.clone(), v.clone());
            c.env_name = env;
            if let Some(e) = emails.first() {
                c.fields.insert("email".into(), serde_json::json!(e));
            }
            if ids.len() == 1 && !UUID.is_match(v) {
                c.fields.insert("id".into(), serde_json::json!(ids[0].0));
            }
            out.push(c);
        }
    }
    report(pending, &mut unmatched);
    pair_up(&mut out);
    out.truncate(MAX_ITEMS);
    Parsed {
        candidates: out,
        unmatched,
    }
}

/// Reports a label line that never got a value, if it looks like it named a
/// credential (rather than being a section heading or dialog text).
fn report(pending: Option<(usize, String)>, out: &mut Vec<Unmatched>) {
    const WORDS: &[&str] = &[
        "key",
        "token",
        "ssh",
        "password",
        "secret",
        "api",
        "apns",
        "login",
        "credential",
        "pat",
    ];
    if let Some((line, text)) = pending
        && words(&text).iter().any(|w| WORDS.iter().any(|k| w.starts_with(k)))
    {
        out.push(Unmatched {
            line,
            text: mask_line(&text),
        });
    }
}

fn words(s: &str) -> Vec<String> {
    s.to_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(String::from)
        .collect()
}

/// Joins values that belong together: "Key - X" followed by "Secret - Y",
/// and a Google OAuth client ID followed by its secret.
fn pair_up(c: &mut Vec<Candidate>) {
    let mut i = 1;
    while i < c.len() {
        let (prev, cur) = (&c[i - 1], &c[i]);
        let pw = words(&prev.label);
        let cw = words(&cur.label);
        let near = cur.line - prev.line <= 2;
        // Only an ID-shaped value (no known key format, fairly short) may
        // become a plaintext ID field; a real key never does.
        let prev_is_id = providers::detect(&prev.material.value, "").is_none() && prev.material.value.len() <= 40;
        let is_id = matches!(pw.last().map(String::as_str), Some("key" | "id" | "keyid"));
        let is_secret = cw.last().map(String::as_str) == Some("secret") && cw.len() <= 2;
        if near && is_id && is_secret && prev_is_id {
            let id_value = prev.material.value.clone();
            let field = if pw.iter().any(|w| w == "client") { "client_id" } else { "key_id" };
            let mut merged = c.remove(i);
            let prev = c.remove(i - 1);
            merged.label = label_of(&prev.label, &[])
                .trim_end_matches(|ch: char| ch.is_alphabetic())
                .trim()
                .to_string();
            if merged.label.chars().filter(char::is_ascii_alphabetic).count() < 2 {
                merged.label = prev.label.clone();
            }
            merged.line = prev.line;
            merged.fields.insert(field.into(), serde_json::json!(id_value));
            c.insert(i - 1, merged);
            continue;
        }
        if cur.material.value.starts_with("GOCSPX-")
            && let Some(j) = (0..i).rev().take(5).find(|&j| GOOGLE_CLIENT_ID.is_match(&c[j].material.value))
        {
            let id = c.remove(j);
            let cur = &mut c[i - 1];
            cur.fields.insert("client_id".into(), serde_json::json!(id.material.value));
            if words(&cur.label).iter().all(|w| w == "client" || w == "secret") {
                cur.label = format!("{} {}", id.label, cur.label);
            }
            continue;
        }
        i += 1;
    }
    // A lone Google client ID isn't a secret.
    c.retain(|x| !GOOGLE_CLIENT_ID.is_match(&x.material.value));
}

impl Candidate {
    fn new(line: usize, label: String, value: String) -> Self {
        Self {
            line,
            label,
            material: Material::single(value.trim()),
            fields: serde_json::Map::new(),
            notes: vec![],
            env_name: None,
        }
    }

    pub fn provider(&self) -> Option<&'static Provider> {
        let fields = serde_json::Value::Object(self.fields.clone());
        providers::detect(&self.material.value, &self.label).map(|p| providers::refine(p, &fields))
    }
}

// ---------------------------------------------------------------- proposals

#[derive(Serialize, Clone)]
pub struct NeedView {
    pub name: &'static str,
    pub label: &'static str,
    pub secret: bool,
    pub hint: &'static str,
}

/// What the owner reviews before importing. Never contains a value.
#[derive(Serialize)]
pub struct Proposal {
    pub id: usize,
    pub line: usize,
    pub label: String,
    pub name: String,
    pub provider: Option<&'static str>,
    pub provider_name: Option<&'static str>,
    pub kind: &'static str,
    pub owner_only: bool,
    pub risk: &'static str,
    pub preview: String,
    /// Plaintext parts found next to the value (key ID, client ID, email...).
    pub fields: serde_json::Map<String, serde_json::Value>,
    /// Parts the provider needs that the file didn't have.
    pub needs: Vec<NeedView>,
    pub notes: String,
    /// Another secret (in the vault, or earlier in the file) with this value.
    pub duplicate_of: Option<String>,
    pub include: bool,
    /// Suggested managing secret, for rotation.
    pub parent: Option<String>,
    pub rotation: &'static str,
}

/// Builds proposals. `existing` is the vault's (name, provider) list;
/// `vault_dup` finds a vault secret already holding a value.
pub fn propose(parsed: &Parsed, existing: &[(String, Option<String>)], vault_dup: impl Fn(&str) -> Option<String>) -> Vec<Proposal> {
    let mut taken: Vec<String> = existing.iter().map(|e| e.0.clone()).collect();
    let mut out: Vec<Proposal> = vec![];
    for (id, c) in parsed.candidates.iter().enumerate() {
        let p = c.provider();
        let name = unique(&suggest_name(c, p), &mut taken);
        let fields_v = serde_json::Value::Object(c.fields.clone());
        let needs = p
            .map(|p| {
                p.needs
                    .iter()
                    .filter(|n| n.name == "base_url" || n.secret || fields_v.get(n.name).is_none())
                    .map(|n| NeedView {
                        name: n.name,
                        label: n.label,
                        secret: n.secret,
                        hint: n.hint,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let in_file = parsed.candidates[..id]
            .iter()
            .position(|o| o.material.value == c.material.value)
            .map(|j| format!("{} (line {})", out[j].name, parsed.candidates[j].line));
        let duplicate_of = in_file.or_else(|| vault_dup(&c.material.value));
        let kind = p.map(|p| p.kind).unwrap_or("api_key");
        out.push(Proposal {
            id,
            line: c.line,
            label: mask_line(&c.label),
            name,
            provider: p.map(|p| p.id),
            provider_name: p.map(|p| p.name),
            kind,
            owner_only: p.is_some_and(|p| p.owner_only) || kind == "password",
            risk: p.map(|p| p.risk).unwrap_or("medium"),
            preview: preview(&c.material.value, p),
            fields: c.fields.clone(),
            needs,
            notes: c.notes.join("\n"),
            include: duplicate_of.is_none(),
            duplicate_of,
            parent: None,
            rotation: p.map(|p| p.rotation.mode()).unwrap_or("guided"),
        });
    }
    // Managers: when exactly one secret of the managing provider exists.
    for i in 0..out.len() {
        let Some(pp) = out[i].provider.and_then(providers::by_id).and_then(|p| p.parent_provider) else {
            continue;
        };
        let mut found: Vec<String> = out
            .iter()
            .enumerate()
            .filter(|(j, o)| *j != i && o.include && o.provider == Some(pp))
            .map(|(_, o)| o.name.clone())
            .collect();
        found.extend(existing.iter().filter(|e| e.1.as_deref() == Some(pp)).map(|e| e.0.clone()));
        if found.len() == 1 {
            out[i].parent = found.pop();
        }
    }
    out
}

// ---------------------------------------------------------------- naming

const STOP: &[&str] = &[
    "api", "key", "keu", "keys", "token", "tokens", "secret", "the", "is", "your", "welcome", "to", "for", "this", "a", "an", "my", "of",
    "in", "and", "with", "value", "code", "it", "be", "will", "here", "private", "access", "pat", "s",
];

/// Conventional environment-variable names, so apps find keys where they expect them.
fn env_default(p: Option<&Provider>) -> String {
    let name = match p.map(|p| p.id) {
        Some("anthropic") => "ANTHROPIC_API_KEY",
        Some("anthropic-admin") => "ANTHROPIC_ADMIN_KEY",
        Some("openrouter") => "OPENROUTER_API_KEY",
        Some("openrouter-management") => "OPENROUTER_MANAGEMENT_KEY",
        Some("openai") => "OPENAI_API_KEY",
        Some("github") => "GITHUB_TOKEN",
        Some("github-app") => "GITHUB_APP_PRIVATE_KEY",
        Some("huggingface") => "HF_TOKEN",
        Some("cloudflare") => "CLOUDFLARE_API_TOKEN",
        Some("unifi") => "UNIFI_API_KEY",
        Some("alphavantage") => "ALPHAVANTAGE_API_KEY",
        Some("finnhub") => "FINNHUB_API_KEY",
        Some("twelvedata") => "TWELVEDATA_API_KEY",
        Some("fmp") => "FMP_API_KEY",
        Some("alpaca-paper") => "ALPACA_PAPER_SECRET_KEY",
        Some("alpaca-live") => "ALPACA_SECRET_KEY",
        Some("n8n") => "N8N_API_KEY",
        Some("google") => "GOOGLE_API_KEY",
        Some("google-stitch") => "STITCH_API_KEY",
        Some("google-oauth-client") => "GOOGLE_CLIENT_SECRET",
        Some("google-service-account") => "GOOGLE_SERVICE_ACCOUNT",
        Some("atlassian") => "ATLASSIAN_API_TOKEN",
        Some("slack") => "SLACK_BOT_TOKEN",
        Some("slack-refresh") => "SLACK_REFRESH_TOKEN",
        Some("tavily") => "TAVILY_API_KEY",
        Some("elevenlabs") => "ELEVENLABS_API_KEY",
        Some("magic-21st") => "MAGIC_API_KEY",
        Some("azure-app-secret") => "AZURE_CLIENT_SECRET",
        Some("tailscale-authkey") => "TS_AUTHKEY",
        Some("tailscale-oauth") => "TS_OAUTH_CLIENT_SECRET",
        Some("tailscale") => "TS_API_KEY",
        Some("crypto-wallet") => "WALLET_PRIVATE_KEY",
        Some("apns") => "APNS_KEY",
        Some("password") => "PASSWORD",
        Some("hostinger") => "HOSTINGER_ROOT_PASSWORD",
        Some("stripe-live") => "STRIPE_SECRET_KEY",
        Some("stripe-test") => "STRIPE_TEST_SECRET_KEY",
        Some("gitlab") => "GITLAB_TOKEN",
        Some("npm") => "NPM_TOKEN",
        Some("digitalocean") => "DIGITALOCEAN_TOKEN",
        Some("replicate") => "REPLICATE_API_TOKEN",
        Some("aws") => "AWS_SECRET_ACCESS_KEY",
        Some("private-key") => "PRIVATE_KEY",
        Some("jwt") => "JWT_TOKEN",
        // Any other known provider: <PROVIDER>_API_KEY, e.g. LINEAR_API_KEY.
        Some(id) => return format!("{}_API_KEY", id.to_ascii_uppercase().replace('-', "_")),
        None => "KEY",
    };
    name.to_string()
}

fn generic_env(n: &str) -> bool {
    matches!(
        n,
        "API_KEY" | "KEY" | "TOKEN" | "SECRET" | "APIKEY" | "ACCESS_TOKEN" | "SECRET_KEY" | "PASSWORD"
    )
}

/// Suggests a name like `OPENROUTER_CHATBOT_API_KEY`: the conventional name
/// for the provider, with distinguishing words from the label.
pub fn suggest_name(c: &Candidate, p: Option<&Provider>) -> String {
    if let Some(e) = &c.env_name
        && !generic_env(e)
    {
        return e.to_ascii_uppercase();
    }
    let base = env_default(p);
    let base = base.as_str();
    // A generic NAME=value inside a command line: the line's other words are
    // command syntax, not a description.
    if c.env_name.is_some() {
        return base.to_string();
    }
    let provider_text = p
        .map(|p| {
            format!("{} {} {}", p.id, p.name, p.hints.join(" "))
                .to_lowercase()
                .replace([' ', '-', '(', ')'], "")
        })
        .unwrap_or_default();
    let keep_hints = p.is_none_or(|p| p.id == "password");
    if p.is_some_and(|p| p.id == "hostinger") {
        return base.to_string();
    }
    let qualifier: Vec<String> = words(&c.label)
        .into_iter()
        .filter(|w| !STOP.contains(&w.as_str()))
        // A word with digits in a label may be part of a value.
        .filter(|w| w.len() <= 4 || !w.chars().any(|c| c.is_ascii_digit()))
        .filter(|w| keep_hints || !(w.len() >= 3 && provider_text.contains(w.as_str())))
        .filter(|w| p.is_none_or(|p| p.id != "password") || !matches!(w.as_str(), "password" | "passwd" | "pwd"))
        .take(3)
        .collect();
    let q = qualifier.join("_").to_ascii_uppercase();
    let name = if q.is_empty() {
        base.to_string()
    } else if base == "KEY" || base == "PASSWORD" {
        format!("{q}_{base}")
    } else {
        // Insert after the provider part: OPENROUTER + _CHATBOT + _API_KEY.
        match base.split_once('_') {
            Some((head, tail)) => format!("{head}_{q}_{tail}"),
            None => format!("{base}_{q}"),
        }
    };
    let name: String = name
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .take(100)
        .collect();
    if name.is_empty() { "IMPORTED_KEY".into() } else { name }
}

/// Makes `name` unique against `taken`, appending _2, _3...
pub fn unique(name: &str, taken: &mut Vec<String>) -> String {
    let mut n = name.to_string();
    let mut k = 2;
    while taken.iter().any(|t| t.eq_ignore_ascii_case(&n)) {
        n = format!("{name}_{k}");
        k += 1;
    }
    taken.push(n.clone());
    n
}

/// The literal start of a format regex that `value` matches, such as
/// `sk-or-v1-` in `^sk-or-v1-[A-Za-z0-9]{32,}$` or `ghp_` in
/// `^(ghp|gho)_...`: the part that's the same for everyone.
fn literal_prefix(pattern: &str, value: &str) -> String {
    let mut out = String::new();
    let mut rest = pattern.strip_prefix('^').unwrap_or("");
    // A leading group of plain alternatives: take the one the value has.
    if let Some(group) = rest.strip_prefix('(')
        && let Some(close) = group.find(')')
        && group[..close].chars().all(|c| c.is_ascii_alphanumeric() || c == '|')
    {
        match group[..close].split('|').find(|alt| value.starts_with(alt)) {
            Some(alt) => out.push_str(alt),
            None => return String::new(),
        }
        rest = &group[close + 1..];
    }
    let mut chars = rest.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek().is_some_and(|n| matches!(n, '-' | '.' | '_')) => out.push(chars.next().expect("peeked")),
            '[' | '(' | '.' | '*' | '+' | '?' | '{' | '|' | '\\' | '$' => break,
            c => out.push(c),
        }
    }
    if value.starts_with(&out) { out } else { String::new() }
}

/// "sk-or-v1-… (73 chars)": only a public format prefix is shown, never a
/// character of the secret itself.
pub fn preview(value: &str, p: Option<&Provider>) -> String {
    let n = value.chars().count();
    let prefix = p
        .filter(|p| p.kind == "api_key")
        .and_then(|p| p.patterns.iter().map(|pat| literal_prefix(pat, value)).find(|pre| !pre.is_empty()))
        .unwrap_or_default();
    if prefix.is_empty() {
        format!("•••• ({n} chars)")
    } else {
        format!("{prefix}… ({n} chars)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(c: char, n: usize) -> String {
        c.to_string().repeat(n)
    }

    /// Shaped like a real notes file, with fake values built at runtime.
    fn sample() -> String {
        [
            format!("Unifi Garage API keu - {}", "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gH"),
            String::new(),
            "GIT TOKEN - Hugginface".into(),
            format!("Github  this is for web-app-project - ghp_{}", r('A', 36)),
            format!("Hugging face - hf_{}", r('b', 34)),
            format!("Cloud flare dns example.ai - {}", "Ab1_".repeat(10)),
            "Market Data:".into(),
            format!("Alpha vantage market data api key : {}", "Q1W2E3R4T5Y6U7I8"),
            format!("Welcome to Alpha Vantage! Your API key is: {}", "Z9X8C7V6B5N4M3L2"),
            format!("Claude api key - sk-ant-api03-{}", r('k', 95)),
            "N8N API KEY -".into(),
            format!("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ{}.{}", r('x', 20), r('s', 43)),
            "Router cabin ssh".into(),
            format!("Openrouter Management Key: sk-or-v1-{}", "0a".repeat(32)),
            format!("chatbot key: sk-or-v1-{}", "1b".repeat(32)),
            format!("Helper-ai-bot secret: abc8Q~{}", "y1".repeat(17)),
            "Once funnel is active, your Azure Bot messaging endpoint will be:".into(),
            "https://box.example.ts.net/api/messages".into(),
            format!("Github  this is for web-app-project - ghp_{}", r('A', 36)),
            format!("Tavily you@example.com : tvly-dev-{}", "Tv9".repeat(16)),
            format!("Alpaca: Key - PK{}", "7Q3R5T".repeat(4)),
            format!("Secret - {}", "aZ9".repeat(14) + "xy"),
            format!(
                r#"❯ claude mcp add magic --scope user --env API_KEY="{}" -- npx -y @21st-dev/magic@latest"#,
                "c0ffee".repeat(10) + "abcd"
            ),
            format!(
                "Google signed: 123456789012-{}.apps.googleusercontent.com",
                "abc123def456".repeat(3)
            ),
            "You will no longer be able to view or download the client secret once you close this dialog.".into(),
            "Client secret".into(),
            format!("GOCSPX-{}", "Gq4".repeat(9) + "z"),
            format!("VPS root password: {}", "Blue Kite 42 &; tree"),
            "ssh root@203.0.113.7".into(),
            format!("Savings private key 0x{}", "9f".repeat(32)),
            "Apple APNS: ABC APNS".into(),
            "Key ID:ABCDE12345".into(),
            "API_TOKEN_FOR_X=plainvalue123456".into(),
            "claude --resume 0f8fad5b-d9cb-469f-a165-70867728950e --dangerously-skip-permissions".into(),
        ]
        .join("\n")
    }

    fn by_label<'a>(p: &'a Parsed, needle: &str) -> &'a Candidate {
        p.candidates
            .iter()
            .find(|c| c.label.to_lowercase().contains(&needle.to_lowercase()))
            .unwrap_or_else(|| panic!("no '{needle}'"))
    }

    #[test]
    fn parses_free_form_notes() {
        let p = parse(&sample());
        let ids: Vec<_> = p.candidates.iter().map(|c| c.provider().map(|p| p.id).unwrap_or("?")).collect();
        assert_eq!(
            ids,
            vec![
                "unifi",
                "github",
                "huggingface",
                "cloudflare",
                "alphavantage",
                "alphavantage",
                "anthropic",
                "n8n",
                "openrouter-management",
                "openrouter",
                "azure-app-secret",
                "github",
                "tavily",
                "alpaca-paper",
                "magic-21st",
                "google-oauth-client",
                "password",
                "crypto-wallet",
                "?"
            ]
        );
        // The JWT on its own line takes the label from the line above.
        assert_eq!(by_label(&p, "n8n").material.value.split('.').count(), 3);
        // Key + Secret lines become one Alpaca secret with its key ID.
        let alpaca = by_label(&p, "alpaca");
        assert!(alpaca.fields["key_id"].as_str().unwrap().starts_with("PK"));
        // The Google client ID is attached to its secret, not stored on its own.
        let g = p.candidates.iter().find(|c| c.material.value.starts_with("GOCSPX-")).unwrap();
        assert!(g.fields["client_id"].as_str().unwrap().ends_with(".apps.googleusercontent.com"));
        // Metadata lines attach to the secret above them.
        let host = by_label(&p, "vps");
        assert_eq!(host.fields["ssh_login"], "root@203.0.113.7");
        assert_eq!(
            host.material.value, "Blue Kite 42 &; tree",
            "passwords keep their spaces and symbols"
        );
        assert_eq!(
            by_label(&p, "helper").notes[0],
            "Related site: https://box.example.ts.net",
            "only the site, never a path"
        );
        assert_eq!(by_label(&p, "tavily").fields["email"], "you@example.com");
        // The magic key comes out of the command line, without the package name.
        let magic = p
            .candidates
            .iter()
            .find(|c| c.provider().is_some_and(|p| p.id == "magic-21st"))
            .unwrap();
        assert_eq!(magic.material.value.len(), 64);
        // Lines with a label but no value are reported.
        let un: Vec<_> = p.unmatched.iter().map(|u| u.text.as_str()).collect();
        assert!(un.contains(&"GIT TOKEN - ‹hidden›"), "anything after 'token -' is masked: {un:?}");
        assert!(un.contains(&"Router cabin ssh"), "{un:?}");
        assert!(un.iter().any(|u| u.contains("APNS")), "{un:?}");
    }

    #[test]
    fn suggests_conventional_unique_names() {
        let p = parse(&sample());
        let mut taken = vec![];
        let names: Vec<String> = p
            .candidates
            .iter()
            .map(|c| unique(&suggest_name(c, c.provider()), &mut taken))
            .collect();
        let want = [
            "UNIFI_GARAGE_API_KEY",
            "GITHUB_WEB_APP_PROJECT_TOKEN",
            "HF_TOKEN",
            "CLOUDFLARE_DNS_EXAMPLE_AI_API_TOKEN",
            "ALPHAVANTAGE_MARKET_DATA_API_KEY",
            "ALPHAVANTAGE_API_KEY",
            "ANTHROPIC_API_KEY",
            "N8N_API_KEY",
            "OPENROUTER_MANAGEMENT_KEY",
            "OPENROUTER_CHATBOT_API_KEY",
            "AZURE_HELPER_AI_BOT_CLIENT_SECRET",
            "GITHUB_WEB_APP_PROJECT_TOKEN_2",
            "TAVILY_API_KEY",
            "ALPACA_PAPER_SECRET_KEY",
            "MAGIC_API_KEY",
            "GOOGLE_SIGNED_CLIENT_SECRET",
            "VPS_ROOT_PASSWORD",
            "WALLET_SAVINGS_PRIVATE_KEY",
            "API_TOKEN_FOR_X",
        ];
        assert_eq!(names, want);
    }

    #[test]
    fn every_known_provider_gets_a_real_name() {
        for p in providers::PROVIDERS {
            assert_ne!(env_default(Some(p)), "KEY", "{} needs a conventional name", p.id);
        }
        let c = |line: String| parse(&line).candidates.remove(0);
        let lin = c(format!("Linear: lin_api_{}", "Ln4".repeat(13) + "x"));
        assert_eq!(suggest_name(&lin, lin.provider()), "LINEAR_API_KEY");
        let st = c(format!("Stripe - sk_live_{}", "St9".repeat(33)));
        assert_eq!(suggest_name(&st, st.provider()), "STRIPE_SECRET_KEY");
        let unknown = c(format!("Mailgun: key-{}", "4f".repeat(16)));
        assert_eq!(
            suggest_name(&unknown, unknown.provider()),
            "MAILGUN_KEY",
            "unknown providers still use the label"
        );
    }

    #[test]
    fn proposals_flag_duplicates_needs_and_managers() {
        let p = parse(&sample());
        let props = propose(&p, &[("ANTHROPIC_API_KEY".into(), Some("anthropic".into()))], |_| None);
        let gh: Vec<_> = props.iter().filter(|x| x.provider == Some("github")).collect();
        assert!(gh[0].include && gh[0].duplicate_of.is_none());
        assert!(!gh[1].include, "the second copy is skipped");
        assert!(
            gh[1]
                .duplicate_of
                .as_deref()
                .unwrap()
                .starts_with("GITHUB_WEB_APP_PROJECT_TOKEN (line")
        );
        let claude = props.iter().find(|x| x.provider == Some("anthropic")).unwrap();
        assert_eq!(claude.name, "ANTHROPIC_API_KEY_2", "names never clash with the vault");
        let or = props.iter().find(|x| x.provider == Some("openrouter")).unwrap();
        assert_eq!(or.parent.as_deref(), Some("OPENROUTER_MANAGEMENT_KEY"));
        let n8n = props.iter().find(|x| x.provider == Some("n8n")).unwrap();
        assert_eq!(n8n.needs.iter().map(|n| n.name).collect::<Vec<_>>(), vec!["base_url"]);
        let azure = props.iter().find(|x| x.provider == Some("azure-app-secret")).unwrap();
        assert_eq!(azure.needs.len(), 2);
        let alpaca = props.iter().find(|x| x.provider == Some("alpaca-paper")).unwrap();
        assert!(alpaca.needs.is_empty(), "the key ID came from the file");
        let wallet = props.iter().find(|x| x.provider == Some("crypto-wallet")).unwrap();
        assert!(wallet.owner_only);
        assert_eq!(wallet.rotation, "never");
        let all = serde_json::to_string(&props.iter().map(|x| (&x.label, &x.preview, &x.notes)).collect::<Vec<_>>()).unwrap();
        for c in &p.candidates {
            assert!(!all.contains(&c.material.value), "no value may appear in a proposal");
        }
        let dup = propose(&p, &[], |v| v.starts_with("hf_").then(|| "OLD_HF".to_string()));
        assert_eq!(
            dup.iter()
                .find(|x| x.provider == Some("huggingface"))
                .unwrap()
                .duplicate_of
                .as_deref(),
            Some("OLD_HF")
        );
    }

    #[test]
    fn values_never_end_up_in_plaintext_metadata() {
        let openai = format!("sk-proj-{}", "Q".repeat(40));
        let hook = format!("https://hooks.slack.com/services/T0123ABCD/B0456EFGH/{}", "Xy7".repeat(8));
        let text = [
            format!("OpenAI key - {openai}"),
            format!("Webhook secret - whsec_{}", "W1".repeat(16)),
            format!("Slack alerts {hook}"),
            "my server root password hunter22x".into(),
            "gmail password correcthorsebatterystaple".into(),
            format!("Stripe - sk_live_{}", "Z".repeat(24)),
        ]
        .join("\n");
        let p = parse(&text);
        let o = p
            .candidates
            .iter()
            .find(|c| c.material.value == openai)
            .expect("the OpenAI key stays a value");
        assert!(o.fields.is_empty(), "a real key is never turned into a plaintext ID");
        assert!(p.candidates.iter().any(|c| c.material.value == hook), "a webhook URL is a secret");
        assert!(p.candidates.iter().any(|c| c.material.value == "hunter22x"));
        assert!(p.candidates.iter().any(|c| c.material.value == "correcthorsebatterystaple"));
        let props = propose(&p, &[], |_| None);
        let meta = serde_json::to_string(&props.iter().map(|x| (&x.label, &x.name, &x.notes, &x.fields)).collect::<Vec<_>>()).unwrap()
            + &serde_json::to_string(&p.unmatched).unwrap();
        for v in [openai.as_str(), &hook, "hunter22x", "correcthorse", "T0123ABCD"] {
            assert!(!meta.contains(v), "{v} leaked into metadata: {meta}");
        }
        assert_eq!(mask_line("gmail password correcthorsebatterystaple"), "gmail password ‹25 chars›");
        assert!(!mask_line("root login hunter22x!").contains("hunter22x"));
    }

    #[test]
    fn env_files() {
        let p = parse("# comment\nexport OPENAI_API_KEY=\"sk-proj-abcdefghijklmnopqrstuvwx\"\nDB_PASSWORD=hunter2hunter2\nEMPTY=\n");
        assert_eq!(p.candidates.len(), 2);
        assert_eq!(p.candidates[0].env_name.as_deref(), Some("OPENAI_API_KEY"));
        assert_eq!(p.candidates[0].material.value, "sk-proj-abcdefghijklmnopqrstuvwx");
        assert_eq!(suggest_name(&p.candidates[1], p.candidates[1].provider()), "DB_PASSWORD");
    }

    #[test]
    fn pem_and_service_account_blocks() {
        // Assembled at runtime so secret scanners don't flag the fixture.
        let (begin, end, sa) = ("-----BEGIN ", "-----END ", ["service", "account"].join("_"));
        let text = format!(
            "GitHub App key for deploys\n{begin}RSA PRIVATE KEY-----\n{}\n{end}RSA PRIVATE KEY-----\n{{\n  \"type\": \"{sa}\",\n  \"private_key\": \"x\"\n}}\n",
            r('M', 64)
        );
        let p = parse(&text);
        assert_eq!(p.candidates.len(), 2);
        assert_eq!(p.candidates[0].provider().unwrap().id, "github-app");
        assert!(p.candidates[0].material.value.ends_with("-----END RSA PRIVATE KEY-----"));
        assert_eq!(p.candidates[1].provider().unwrap().id, "google-service-account");
    }

    #[test]
    fn previews_and_masking_hide_values() {
        let or = format!("sk-or-v1-{}", "0a".repeat(32));
        assert_eq!(preview(&or, providers::by_id("openrouter")), "sk-or-v1-… (73 chars)");
        assert_eq!(
            preview(&format!("ghp_{}", r('A', 36)), providers::by_id("github")),
            "ghp_… (40 chars)"
        );
        assert_eq!(
            preview(&format!("abc8Q~{}", "y1".repeat(17)), providers::by_id("azure-app-secret")),
            "•••• (40 chars)"
        );
        assert_eq!(
            preview(&"Ab1_".repeat(10), providers::by_id("cloudflare")),
            "•••• (40 chars)",
            "legacy tokens have no public prefix"
        );
        assert_eq!(
            literal_prefix(r"^sk-ant-api\d\d-[A-Za-z0-9_\-]{20,}$", "sk-ant-api03-x"),
            "sk-ant-api"
        );
        assert_eq!(literal_prefix(r"^(sk|rk)_live_[A-Za-z0-9]{20,}$", "rk_live_abc"), "rk_live_");
        assert_eq!(literal_prefix(r"^[A-Za-z0-9_~.\-]{3}\dQ~", "abc8Q~"), "");
        assert_eq!(preview("hunter2hunter2", providers::by_id("password")), "•••• (14 chars)");
        assert_eq!(preview("Q1W2E3R4T5Y6U7I8", providers::by_id("alphavantage")), "•••• (16 chars)");
        let m = mask_line(&format!("Openrouter key: {or}"));
        assert!(!m.contains("0a0a"), "{m}");
        assert_eq!(mask_line("VPS root password: Tall %Oak #7 river"), "VPS root password: ‹hidden›");
        assert_eq!(mask_line("Key ID:ABCDE12345"), "Key ID:‹hidden›");
        assert_eq!(mask_line("Router cabin ssh"), "Router cabin ssh");
    }
}
