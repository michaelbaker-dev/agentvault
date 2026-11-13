//! SQLite storage. Secret values are stored only as ciphertext; everything
//! else (names, descriptions, usage events) is plaintext metadata.

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use std::{collections::HashMap, path::Path, sync::Mutex};

use crate::crypto::sha256;

pub struct Db {
    conn: Mutex<Connection>,
}

pub type DbResult<T> = Result<T, rusqlite::Error>;

/// One encrypted version of a secret.
pub struct VersionCt {
    pub version: i64,
    pub value_ct: Vec<u8>,
    pub dek_ct: Vec<u8>,
    /// See [`crate::material`].
    pub format: i64,
    /// The provider's own ID for this key, used to revoke it after rotation.
    pub provider_ref: Option<String>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS secrets (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    notes           TEXT NOT NULL DEFAULT '',
    tags            TEXT NOT NULL DEFAULT '[]',
    description     TEXT NOT NULL DEFAULT '',
    provider        TEXT,
    provider_name   TEXT,
    risk            TEXT,
    risk_reason     TEXT,
    facts           TEXT NOT NULL DEFAULT '{}',
    docs_url        TEXT,
    rotate_url      TEXT,
    describe_status TEXT NOT NULL DEFAULT 'pending',
    proxy_base_url  TEXT,
    proxy_auth      TEXT,
    version         INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    last_used_at    INTEGER,
    use_count       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS secret_versions (
    secret_id  INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version    INTEGER NOT NULL,
    value_ct   BLOB NOT NULL,
    dek_ct     BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (secret_id, version)
);
CREATE TABLE IF NOT EXISTS tokens (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL,
    hash         BLOB NOT NULL UNIQUE,
    scopes       TEXT NOT NULL,
    secrets      TEXT NOT NULL,
    nodes        TEXT NOT NULL,
    proxy_get_only INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at   INTEGER
);
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    node        TEXT NOT NULL,
    user        TEXT NOT NULL,
    ip          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    secret      TEXT,
    status      INTEGER NOT NULL,
    latency_us  INTEGER NOT NULL,
    upstream_us INTEGER,
    detail      TEXT,
    prev_hash   BLOB NOT NULL,
    hash        BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS rotations (
    id           INTEGER PRIMARY KEY,
    secret_id    INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    mode         TEXT NOT NULL,
    state        TEXT NOT NULL,
    old_version  INTEGER,
    new_version  INTEGER,
    old_ref      TEXT,
    revoke_after INTEGER,
    started_at   INTEGER NOT NULL,
    finished_at  INTEGER,
    actor        TEXT NOT NULL,
    message      TEXT
);
CREATE INDEX IF NOT EXISTS rotations_secret ON rotations(secret_id, id);
-- "Needs attention" items the owner OK'd. `fp` pins the situation that was
-- OK'd (key version, expiry, rotation id...); when it changes the item returns.
CREATE TABLE IF NOT EXISTS attention_acks (
    secret_id    INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,
    fp           TEXT NOT NULL,
    acked_at     INTEGER NOT NULL,
    PRIMARY KEY (secret_id, kind)
);
"#;

/// Columns added after the first release: (table, column, definition).
const MIGRATIONS: &[(&str, &str, &str)] = &[
    ("tokens", "proxy_get_only", "INTEGER NOT NULL DEFAULT 0"),
    ("secrets", "kind", "TEXT NOT NULL DEFAULT 'api_key'"),
    ("secrets", "owner_only", "INTEGER NOT NULL DEFAULT 0"),
    ("secrets", "fields", "TEXT NOT NULL DEFAULT '{}'"),
    ("secrets", "parts", "TEXT NOT NULL DEFAULT '[]'"),
    ("secrets", "parent", "TEXT"),
    ("secrets", "rotate_every_days", "INTEGER"),
    ("secrets", "rotated_at", "INTEGER"),
    ("secrets", "expires_at", "INTEGER"),
    ("secrets", "exposed", "TEXT"),
    ("secrets", "value_mac", "BLOB"),
    ("secrets", "provider_hint", "TEXT"),
    ("secrets", "version_seq", "INTEGER NOT NULL DEFAULT 0"),
    ("secret_versions", "format", "INTEGER NOT NULL DEFAULT 0"),
    ("secret_versions", "provider_ref", "TEXT"),
    ("rotations", "rotator", "TEXT"),
];

#[derive(Debug, Clone, Serialize)]
pub struct SecretMeta {
    #[serde(skip)]
    pub id: i64,
    pub name: String,
    pub notes: String,
    pub tags: Vec<String>,
    pub description: String,
    pub provider: Option<String>,
    pub provider_name: Option<String>,
    pub risk: Option<String>,
    pub risk_reason: Option<String>,
    pub facts: serde_json::Value,
    pub docs_url: Option<String>,
    pub rotate_url: Option<String>,
    pub describe_status: String,
    pub proxy_base_url: Option<String>,
    pub proxy_auth: Option<String>,
    pub version: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_used_at: Option<i64>,
    pub use_count: i64,
    /// api_key, password, private_key or other.
    pub kind: String,
    /// No token can see or use it, whatever its scopes.
    pub owner_only: bool,
    /// Non-secret parts (client ID, account email, site): plaintext.
    pub fields: serde_json::Value,
    /// Names of extra secret parts stored encrypted next to the value.
    pub parts: Vec<String>,
    /// The secret that can create and revoke this one, for rotation.
    pub parent: Option<String>,
    pub rotate_every_days: Option<i64>,
    pub rotated_at: Option<i64>,
    pub expires_at: Option<i64>,
    /// Why this value should be treated as leaked; cleared by a new value.
    pub exposed: Option<String>,
    #[serde(skip)]
    pub value_mac: Option<Vec<u8>>,
    /// Provider chosen by the owner, overriding detection.
    pub provider_hint: Option<String>,
}

/// Settings only the owner may change (they decide who can see a secret
/// and where its value can be sent). `None` leaves a setting as it is.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    pub kind: Option<String>,
    pub owner_only: Option<bool>,
    pub fields: Option<serde_json::Value>,
    pub parent: Option<Option<String>>,
    pub rotate_every_days: Option<Option<i64>>,
    pub expires_at: Option<Option<i64>>,
    pub exposed: Option<Option<String>>,
    pub provider_hint: Option<Option<String>>,
}

/// A new value: format and parts describe the plaintext, `mac` is its
/// duplicate-detection fingerprint.
pub struct NewValue<'a> {
    pub format: i64,
    pub parts: &'a [String],
    pub mac: &'a [u8],
    pub provider_ref: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RotationRow {
    pub id: i64,
    #[serde(skip)]
    pub secret_id: i64,
    pub secret: String,
    /// auto or guided.
    pub mode: String,
    /// running, grace, done, failed or manual_revoke.
    pub state: String,
    pub old_version: Option<i64>,
    pub new_version: Option<i64>,
    #[serde(skip)]
    pub old_ref: Option<String>,
    pub revoke_after: Option<i64>,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub actor: String,
    pub message: Option<String>,
    /// Which provider API revokes the old key, fixed when the rotation switched over.
    #[serde(skip)]
    pub rotator: Option<String>,
}

/// What the describer learned about a secret.
#[derive(Debug, Clone, Default)]
pub struct Description {
    pub description: String,
    pub provider: Option<String>,
    pub provider_name: Option<String>,
    pub risk: Option<String>,
    pub risk_reason: Option<String>,
    pub facts: serde_json::Value,
    pub docs_url: Option<String>,
    pub rotate_url: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenRow {
    pub id: i64,
    pub name: String,
    pub scopes: Vec<String>,
    pub secrets: Vec<String>,
    pub nodes: Vec<String>,
    pub proxy_get_only: bool,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NewEvent {
    pub ts: i64,
    pub node: String,
    pub user: String,
    pub ip: String,
    pub actor: String,
    pub action: String,
    pub secret: Option<String>,
    pub status: i64,
    pub latency_us: i64,
    pub upstream_us: Option<i64>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EventRow {
    pub id: i64,
    pub ts: i64,
    pub node: String,
    pub user: String,
    pub ip: String,
    pub actor: String,
    pub action: String,
    pub secret: Option<String>,
    pub status: i64,
    pub latency_us: i64,
    pub upstream_us: Option<i64>,
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuditReport {
    pub ok: bool,
    pub checked: u64,
    pub first_bad_id: Option<i64>,
    pub head: Option<String>,
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

const SECRET_COLS: &str = "id, name, notes, tags, description, provider, provider_name, risk, risk_reason, \
    facts, docs_url, rotate_url, describe_status, proxy_base_url, proxy_auth, version, created_at, \
    updated_at, last_used_at, use_count, kind, owner_only, fields, parts, parent, rotate_every_days, \
    rotated_at, expires_at, exposed, value_mac, provider_hint";

fn secret_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SecretMeta> {
    let tags: String = r.get(3)?;
    let facts: String = r.get(9)?;
    Ok(SecretMeta {
        id: r.get(0)?,
        name: r.get(1)?,
        notes: r.get(2)?,
        tags: serde_json::from_str(&tags).unwrap_or_default(),
        description: r.get(4)?,
        provider: r.get(5)?,
        provider_name: r.get(6)?,
        risk: r.get(7)?,
        risk_reason: r.get(8)?,
        facts: serde_json::from_str(&facts).unwrap_or(serde_json::Value::Null),
        docs_url: r.get(10)?,
        rotate_url: r.get(11)?,
        describe_status: r.get(12)?,
        proxy_base_url: r.get(13)?,
        proxy_auth: r.get(14)?,
        version: r.get(15)?,
        created_at: r.get(16)?,
        updated_at: r.get(17)?,
        last_used_at: r.get(18)?,
        use_count: r.get(19)?,
        kind: r.get(20)?,
        owner_only: r.get(21)?,
        fields: serde_json::from_str(&r.get::<_, String>(22)?).unwrap_or_else(|_| serde_json::json!({})),
        parts: serde_json::from_str(&r.get::<_, String>(23)?).unwrap_or_default(),
        parent: r.get(24)?,
        rotate_every_days: r.get(25)?,
        rotated_at: r.get(26)?,
        expires_at: r.get(27)?,
        exposed: r.get(28)?,
        value_mac: r.get(29)?,
        provider_hint: r.get(30)?,
    })
}

const ROTATION_COLS: &str = "r.id, r.secret_id, s.name, r.mode, r.state, r.old_version, r.new_version, r.old_ref, \
    r.revoke_after, r.started_at, r.finished_at, r.actor, r.message, r.rotator";

fn rotation_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<RotationRow> {
    Ok(RotationRow {
        id: r.get(0)?,
        secret_id: r.get(1)?,
        secret: r.get(2)?,
        mode: r.get(3)?,
        state: r.get(4)?,
        old_version: r.get(5)?,
        new_version: r.get(6)?,
        old_ref: r.get(7)?,
        revoke_after: r.get(8)?,
        started_at: r.get(9)?,
        finished_at: r.get(10)?,
        actor: r.get(11)?,
        message: r.get(12)?,
        rotator: r.get(13)?,
    })
}

fn enc_err(e: crate::vault::VaultError) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(e.to_string().into())
}

fn event_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<EventRow> {
    Ok(EventRow {
        id: r.get(0)?,
        ts: r.get(1)?,
        node: r.get(2)?,
        user: r.get(3)?,
        ip: r.get(4)?,
        actor: r.get(5)?,
        action: r.get(6)?,
        secret: r.get(7)?,
        status: r.get(8)?,
        latency_us: r.get(9)?,
        upstream_us: r.get(10)?,
        detail: r.get(11)?,
    })
}

const EVENT_COLS: &str = "id, ts, node, user, ip, actor, action, secret, status, latency_us, upstream_us, detail";

/// Hash-chain link: sha256(prev_hash || canonical JSON of the event's fields).
fn event_hash(prev: &[u8], e: &EventRow) -> [u8; 32] {
    let fields = serde_json::json!([
        e.ts, e.node, e.user, e.ip, e.actor, e.action, e.secret, e.status, e.latency_us, e.upstream_us, e.detail
    ]);
    let mut buf = prev.to_vec();
    buf.extend_from_slice(&serde_json::to_vec(&fields).expect("json"));
    sha256(&buf)
}

fn apply_settings(tx: &rusqlite::Transaction<'_>, id: i64, st: &Settings) -> DbResult<()> {
    if let Some(k) = &st.kind {
        tx.execute("UPDATE secrets SET kind = ?2 WHERE id = ?1", params![id, k])?;
    }
    if let Some(o) = st.owner_only {
        tx.execute("UPDATE secrets SET owner_only = ?2 WHERE id = ?1", params![id, o])?;
    }
    if let Some(f) = &st.fields {
        tx.execute("UPDATE secrets SET fields = ?2 WHERE id = ?1", params![id, f.to_string()])?;
    }
    if let Some(p) = &st.parent {
        tx.execute("UPDATE secrets SET parent = ?2 WHERE id = ?1", params![id, p])?;
    }
    if let Some(d) = st.rotate_every_days {
        tx.execute("UPDATE secrets SET rotate_every_days = ?2 WHERE id = ?1", params![id, d])?;
    }
    if let Some(e) = st.expires_at {
        tx.execute("UPDATE secrets SET expires_at = ?2 WHERE id = ?1", params![id, e])?;
    }
    if let Some(x) = &st.exposed {
        tx.execute("UPDATE secrets SET exposed = ?2 WHERE id = ?1", params![id, x])?;
    }
    if let Some(x) = &st.provider_hint {
        tx.execute("UPDATE secrets SET provider_hint = ?2 WHERE id = ?1", params![id, x])?;
    }
    Ok(())
}

impl Db {
    pub fn open(path: &Path) -> DbResult<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    #[cfg(test)]
    pub fn memory() -> DbResult<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> DbResult<Self> {
        // secure_delete overwrites freed pages, so deleted ciphertext doesn't linger on disk.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON; PRAGMA busy_timeout=5000;",
        )?;
        conn.execute_batch(SCHEMA)?;
        for (table, col, def) in MIGRATIONS {
            let exists = conn.prepare(&format!("SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1"))?.exists([col])?;
            if !exists {
                conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {col} {def}"))?;
            }
        }
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn c(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    // ---- meta ----

    pub fn meta_get(&self, key: &str) -> DbResult<Option<Vec<u8>>> {
        self.c()
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()
    }

    pub fn meta_set_many(&self, items: &[(&str, &[u8])]) -> DbResult<()> {
        let mut c = self.c();
        let tx = c.transaction()?;
        for (k, v) in items {
            tx.execute(
                "INSERT INTO meta(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![k, v],
            )?;
        }
        tx.commit()
    }

    // ---- secrets ----

    pub fn secret_list(&self) -> DbResult<Vec<SecretMeta>> {
        let c = self.c();
        let mut st = c.prepare(&format!("SELECT {SECRET_COLS} FROM secrets ORDER BY name"))?;
        let rows = st.query_map([], secret_from_row)?;
        rows.collect()
    }

    pub fn secret_by_id(&self, id: i64) -> DbResult<Option<SecretMeta>> {
        self.c()
            .query_row(&format!("SELECT {SECRET_COLS} FROM secrets WHERE id = ?1"), [id], secret_from_row)
            .optional()
    }

    pub fn secret_get(&self, name: &str) -> DbResult<Option<SecretMeta>> {
        self.c()
            .query_row(&format!("SELECT {SECRET_COLS} FROM secrets WHERE name = ?1"), [name], secret_from_row)
            .optional()
    }

    /// Inserts a secret and its first version atomically. `encrypt` receives the
    /// new row id and version so the ciphertext can be bound to them.
    pub fn secret_create(
        &self,
        name: &str,
        notes: &str,
        tags: &[String],
        settings: &Settings,
        v: &NewValue<'_>,
        encrypt: impl FnOnce(i64, i64) -> Result<(Vec<u8>, Vec<u8>), crate::vault::VaultError>,
    ) -> DbResult<i64> {
        let now = now_ms();
        let mut c = self.c();
        let tx = c.transaction()?;
        tx.execute(
            "INSERT INTO secrets(name, notes, tags, version, version_seq, created_at, updated_at, parts, value_mac) \
             VALUES (?1, ?2, ?3, 1, 1, ?4, ?4, ?5, ?6)",
            params![name, notes, serde_json::to_string(tags).expect("json"), now, serde_json::to_string(v.parts).expect("json"), v.mac],
        )?;
        let id = tx.last_insert_rowid();
        apply_settings(&tx, id, settings)?;
        let (value_ct, dek_ct) = encrypt(id, 1).map_err(enc_err)?;
        tx.execute(
            "INSERT INTO secret_versions(secret_id, version, value_ct, dek_ct, created_at, format, provider_ref) \
             VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6)",
            params![id, value_ct, dek_ct, now, v.format, v.provider_ref],
        )?;
        tx.commit()?;
        Ok(id)
    }

    /// Adds a version and makes it current. A new value is no longer the one
    /// that leaked, so the exposure flag is cleared.
    pub fn secret_add_version(
        &self,
        id: i64,
        v: &NewValue<'_>,
        encrypt: impl FnOnce(i64, i64) -> Result<(Vec<u8>, Vec<u8>), crate::vault::VaultError>,
    ) -> DbResult<i64> {
        let now = now_ms();
        let mut c = self.c();
        let tx = c.transaction()?;
        // Versions are never reused, even after old ones are rolled back and deleted.
        let (current, seq): (i64, i64) =
            tx.query_row("SELECT version, version_seq FROM secrets WHERE id = ?1", [id], |r| Ok((r.get(0)?, r.get(1)?)))?;
        let highest: i64 =
            tx.query_row("SELECT COALESCE(MAX(version), 0) FROM secret_versions WHERE secret_id = ?1", [id], |r| r.get(0))?;
        let version = current.max(highest).max(seq) + 1;
        let (value_ct, dek_ct) = encrypt(id, version).map_err(enc_err)?;
        tx.execute(
            "INSERT INTO secret_versions(secret_id, version, value_ct, dek_ct, created_at, format, provider_ref) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![id, version, value_ct, dek_ct, now, v.format, v.provider_ref],
        )?;
        tx.execute(
            "UPDATE secrets SET version = ?2, version_seq = ?2, updated_at = ?3, describe_status = 'pending', parts = ?4, \
             value_mac = ?5, exposed = NULL, expires_at = NULL WHERE id = ?1",
            params![id, version, now, serde_json::to_string(v.parts).expect("json"), v.mac],
        )?;
        tx.commit()?;
        Ok(version)
    }

    fn version_query(&self, id: i64, version: Option<i64>) -> DbResult<Option<VersionCt>> {
        let sql = "SELECT v.version, v.value_ct, v.dek_ct, v.format, v.provider_ref FROM secret_versions v \
                   JOIN secrets s ON s.id = v.secret_id WHERE s.id = ?1 AND v.version = COALESCE(?2, s.version)";
        self.c()
            .query_row(sql, params![id, version], |r| {
                Ok(VersionCt { version: r.get(0)?, value_ct: r.get(1)?, dek_ct: r.get(2)?, format: r.get(3)?, provider_ref: r.get(4)? })
            })
            .optional()
    }

    /// The current version's ciphertext.
    pub fn secret_ciphertext(&self, id: i64) -> DbResult<Option<VersionCt>> {
        self.version_query(id, None)
    }

    pub fn version_ciphertext(&self, id: i64, version: i64) -> DbResult<Option<VersionCt>> {
        self.version_query(id, Some(version))
    }

    pub fn version_set_provider_ref(&self, id: i64, version: i64, r: Option<&str>) -> DbResult<()> {
        self.c().execute(
            "UPDATE secret_versions SET provider_ref = ?3 WHERE secret_id = ?1 AND version = ?2",
            params![id, version, r],
        )?;
        Ok(())
    }

    /// Erases an old version (never the current one).
    pub fn version_delete(&self, id: i64, version: i64) -> DbResult<bool> {
        let n = self.c().execute(
            "DELETE FROM secret_versions WHERE secret_id = ?1 AND version = ?2 \
             AND version <> (SELECT version FROM secrets WHERE id = ?1)",
            params![id, version],
        )?;
        Ok(n > 0)
    }

    /// Makes an older, still-stored version current again (rotation rollback).
    pub fn version_restore(&self, id: i64, version: i64) -> DbResult<bool> {
        let n = self.c().execute(
            "UPDATE secrets SET version = ?2, updated_at = ?3 WHERE id = ?1 \
             AND EXISTS (SELECT 1 FROM secret_versions WHERE secret_id = ?1 AND version = ?2)",
            params![id, version, now_ms()],
        )?;
        Ok(n > 0)
    }

    /// Restores the duplicate fingerprint and parts after a rollback.
    pub fn secret_set_value_meta(&self, id: i64, parts: &[String], mac: &[u8]) -> DbResult<()> {
        self.c().execute(
            "UPDATE secrets SET parts = ?2, value_mac = ?3 WHERE id = ?1",
            params![id, serde_json::to_string(parts).expect("json"), mac],
        )?;
        Ok(())
    }

    /// Another secret whose current value has this fingerprint.
    pub fn secret_by_mac(&self, mac: &[u8], except: Option<i64>) -> DbResult<Option<String>> {
        self.c()
            .query_row(
                "SELECT name FROM secrets WHERE value_mac = ?1 AND id <> COALESCE(?2, -1) ORDER BY id LIMIT 1",
                params![mac, except],
                |r| r.get(0),
            )
            .optional()
    }

    pub fn secret_set_settings(&self, id: i64, settings: &Settings) -> DbResult<()> {
        let mut c = self.c();
        let tx = c.transaction()?;
        apply_settings(&tx, id, settings)?;
        tx.execute("UPDATE secrets SET updated_at = ?2 WHERE id = ?1", params![id, now_ms()])?;
        tx.commit()
    }

    /// Records an expiry learned from the provider, if the value is unchanged.
    pub fn secret_set_expiry(&self, id: i64, version: i64, expires_at: Option<i64>) -> DbResult<()> {
        self.c().execute(
            "UPDATE secrets SET expires_at = ?3 WHERE id = ?1 AND version = ?2",
            params![id, version, expires_at],
        )?;
        Ok(())
    }

    pub fn secret_mark_rotated(&self, id: i64) -> DbResult<()> {
        self.c().execute("UPDATE secrets SET rotated_at = ?2 WHERE id = ?1", params![id, now_ms()])?;
        Ok(())
    }

    pub fn secret_update_fields(
        &self,
        id: i64,
        name: Option<&str>,
        notes: Option<&str>,
        tags: Option<&[String]>,
        proxy: Option<(Option<&str>, Option<&str>)>,
    ) -> DbResult<()> {
        let mut c = self.c();
        let tx = c.transaction()?;
        let now = now_ms();
        if let Some(n) = name {
            tx.execute("UPDATE secrets SET name = ?2 WHERE id = ?1", params![id, n])?;
        }
        if let Some(n) = notes {
            tx.execute("UPDATE secrets SET notes = ?2 WHERE id = ?1", params![id, n])?;
        }
        if let Some(t) = tags {
            tx.execute(
                "UPDATE secrets SET tags = ?2 WHERE id = ?1",
                params![id, serde_json::to_string(t).expect("json")],
            )?;
        }
        if let Some((base, auth)) = proxy {
            tx.execute(
                "UPDATE secrets SET proxy_base_url = ?2, proxy_auth = ?3 WHERE id = ?1",
                params![id, base, auth],
            )?;
        }
        tx.execute("UPDATE secrets SET updated_at = ?2 WHERE id = ?1", params![id, now])?;
        tx.commit()
    }

    /// Saves a description, but only if the value hasn't changed since it was
    /// described (otherwise a slow describer could attach the wrong provider).
    pub fn secret_set_description(&self, id: i64, version: i64, d: &Description) -> DbResult<()> {
        self.c().execute(
            "UPDATE secrets SET description = ?2, provider = ?3, provider_name = ?4, risk = ?5, risk_reason = ?6, \
             facts = ?7, docs_url = ?8, rotate_url = ?9, describe_status = ?10 WHERE id = ?1 AND version = ?11",
            params![
                id,
                d.description,
                d.provider,
                d.provider_name,
                d.risk,
                d.risk_reason,
                d.facts.to_string(),
                d.docs_url,
                d.rotate_url,
                d.status,
                version
            ],
        )?;
        Ok(())
    }

    /// Records the locally detected provider straight away, before the
    /// (slower) describer runs.
    pub fn secret_set_provider(&self, id: i64, provider: &str, provider_name: &str, risk: &str) -> DbResult<()> {
        self.c().execute(
            "UPDATE secrets SET provider = ?2, provider_name = ?3, risk = COALESCE(risk, ?4) WHERE id = ?1",
            params![id, provider, provider_name, risk],
        )?;
        Ok(())
    }

    pub fn secret_set_describe_status(&self, id: i64, status: &str) -> DbResult<()> {
        self.c().execute("UPDATE secrets SET describe_status = ?2 WHERE id = ?1", params![id, status])?;
        Ok(())
    }

    pub fn secret_touch(&self, id: i64) -> DbResult<()> {
        self.c().execute(
            "UPDATE secrets SET use_count = use_count + 1, last_used_at = ?2 WHERE id = ?1",
            params![id, now_ms()],
        )?;
        Ok(())
    }

    pub fn secret_delete(&self, id: i64) -> DbResult<()> {
        self.c().execute("DELETE FROM secrets WHERE id = ?1", [id])?;
        Ok(())
    }

    // ---- tokens ----

    pub fn token_create(
        &self,
        name: &str,
        hash: &[u8],
        scopes: &[String],
        secrets: &[String],
        nodes: &[String],
        proxy_get_only: bool,
    ) -> DbResult<i64> {
        let c = self.c();
        c.execute(
            "INSERT INTO tokens(name, hash, scopes, secrets, nodes, created_at, proxy_get_only) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                name,
                hash,
                serde_json::to_string(scopes).expect("json"),
                serde_json::to_string(secrets).expect("json"),
                serde_json::to_string(nodes).expect("json"),
                now_ms(),
                proxy_get_only
            ],
        )?;
        Ok(c.last_insert_rowid())
    }

    fn token_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<TokenRow> {
        let scopes: String = r.get(2)?;
        let secrets: String = r.get(3)?;
        let nodes: String = r.get(4)?;
        Ok(TokenRow {
            id: r.get(0)?,
            name: r.get(1)?,
            scopes: serde_json::from_str(&scopes).unwrap_or_default(),
            secrets: serde_json::from_str(&secrets).unwrap_or_default(),
            nodes: serde_json::from_str(&nodes).unwrap_or_default(),
            created_at: r.get(5)?,
            last_used_at: r.get(6)?,
            revoked_at: r.get(7)?,
            proxy_get_only: r.get(8)?,
        })
    }

    pub fn token_list(&self) -> DbResult<Vec<TokenRow>> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT id, name, scopes, secrets, nodes, created_at, last_used_at, revoked_at, proxy_get_only FROM tokens ORDER BY id DESC",
        )?;
        let rows = st.query_map([], Self::token_from_row)?;
        rows.collect()
    }

    pub fn token_by_hash(&self, hash: &[u8]) -> DbResult<Option<TokenRow>> {
        self.c()
            .query_row(
                "SELECT id, name, scopes, secrets, nodes, created_at, last_used_at, revoked_at, proxy_get_only FROM tokens \
                 WHERE hash = ?1 AND revoked_at IS NULL",
                [hash],
                Self::token_from_row,
            )
            .optional()
    }

    pub fn token_get(&self, id: i64) -> DbResult<Option<TokenRow>> {
        self.c()
            .query_row(
                "SELECT id, name, scopes, secrets, nodes, created_at, last_used_at, revoked_at, proxy_get_only FROM tokens WHERE id = ?1",
                [id],
                Self::token_from_row,
            )
            .optional()
    }

    /// Changes an active token's settings. False if it doesn't exist or was revoked.
    pub fn token_update(
        &self,
        id: i64,
        name: &str,
        scopes: &[String],
        secrets: &[String],
        nodes: &[String],
        proxy_get_only: bool,
    ) -> DbResult<bool> {
        let n = self.c().execute(
            "UPDATE tokens SET name = ?2, scopes = ?3, secrets = ?4, nodes = ?5, proxy_get_only = ?6 \
             WHERE id = ?1 AND revoked_at IS NULL",
            params![
                id,
                name,
                serde_json::to_string(scopes).expect("json"),
                serde_json::to_string(secrets).expect("json"),
                serde_json::to_string(nodes).expect("json"),
                proxy_get_only
            ],
        )?;
        Ok(n > 0)
    }

    pub fn token_touch(&self, id: i64) -> DbResult<()> {
        self.c().execute("UPDATE tokens SET last_used_at = ?2 WHERE id = ?1", params![id, now_ms()])?;
        Ok(())
    }

    pub fn token_revoke(&self, id: i64) -> DbResult<bool> {
        let n = self.c().execute(
            "UPDATE tokens SET revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL",
            params![id, now_ms()],
        )?;
        Ok(n > 0)
    }

    // ---- events ----

    pub fn event_insert(&self, e: NewEvent) -> DbResult<()> {
        let mut c = self.c();
        let tx = c.transaction()?;
        let prev: Vec<u8> = tx
            .query_row("SELECT hash FROM events ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
            .optional()?
            .unwrap_or_else(|| vec![0u8; 32]);
        let row = EventRow {
            id: 0,
            ts: e.ts,
            node: e.node,
            user: e.user,
            ip: e.ip,
            actor: e.actor,
            action: e.action,
            secret: e.secret,
            status: e.status,
            latency_us: e.latency_us,
            upstream_us: e.upstream_us,
            detail: e.detail,
        };
        let hash = event_hash(&prev, &row);
        tx.execute(
            "INSERT INTO events(ts, node, user, ip, actor, action, secret, status, latency_us, upstream_us, detail, prev_hash, hash) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                row.ts, row.node, row.user, row.ip, row.actor, row.action, row.secret, row.status, row.latency_us,
                row.upstream_us, row.detail, prev, hash.to_vec()
            ],
        )?;
        tx.commit()
    }

    pub fn events_since(&self, since_ms: i64, limit: i64) -> DbResult<Vec<EventRow>> {
        let c = self.c();
        let mut st = c.prepare(&format!("SELECT {EVENT_COLS} FROM events WHERE ts >= ?1 ORDER BY id ASC LIMIT ?2"))?;
        let rows = st.query_map(params![since_ms, limit], event_from_row)?;
        rows.collect()
    }

    pub fn events_page(&self, before_id: Option<i64>, limit: i64) -> DbResult<Vec<EventRow>> {
        let c = self.c();
        let mut st = c.prepare(&format!("SELECT {EVENT_COLS} FROM events WHERE id < ?1 ORDER BY id DESC LIMIT ?2"))?;
        let rows = st.query_map(params![before_id.unwrap_or(i64::MAX), limit], event_from_row)?;
        rows.collect()
    }

    /// Deletes a prefix of the log (by id, so a clock jump can't punch holes
    /// in the hash chain).
    pub fn events_prune(&self, before_ms: i64) -> DbResult<usize> {
        self.c().execute(
            "DELETE FROM events WHERE id < COALESCE((SELECT MIN(id) FROM events WHERE ts >= ?1), \
             (SELECT MAX(id) + 1 FROM events), 0)",
            [before_ms],
        )
    }

    /// Walks the hash chain. The first surviving row's prev_hash is the trust
    /// anchor (older rows may have been pruned by retention).
    pub fn audit_verify(&self) -> DbResult<AuditReport> {
        let c = self.c();
        let mut st = c.prepare(&format!("SELECT {EVENT_COLS}, prev_hash, hash FROM events ORDER BY id ASC"))?;
        let mut rows = st.query([])?;
        let mut expected_prev: Option<Vec<u8>> = None;
        let mut checked = 0u64;
        let mut head = None;
        while let Some(r) = rows.next()? {
            let e = event_from_row(r)?;
            let prev: Vec<u8> = r.get(12)?;
            let hash: Vec<u8> = r.get(13)?;
            let link_ok = expected_prev.as_ref().is_none_or(|p| *p == prev);
            if !link_ok || event_hash(&prev, &e).as_slice() != hash.as_slice() {
                return Ok(AuditReport { ok: false, checked, first_bad_id: Some(e.id), head: None });
            }
            checked += 1;
            head = Some(hex::encode(&hash));
            expected_prev = Some(hash);
        }
        Ok(AuditReport { ok: true, checked, first_bad_id: None, head })
    }

    // ---- rotations ----

    pub fn rotation_insert(&self, secret_id: i64, mode: &str, actor: &str, old_version: Option<i64>) -> DbResult<i64> {
        let c = self.c();
        c.execute(
            "INSERT INTO rotations(secret_id, mode, state, old_version, started_at, actor) VALUES (?1, ?2, 'running', ?3, ?4, ?5)",
            params![secret_id, mode, old_version, now_ms(), actor],
        )?;
        Ok(c.last_insert_rowid())
    }

    /// Updates a rotation. `finished` stamps finished_at.
    #[allow(clippy::too_many_arguments)]
    pub fn rotation_update(
        &self,
        id: i64,
        state: &str,
        new_version: Option<i64>,
        old_ref: Option<&str>,
        revoke_after: Option<i64>,
        message: Option<&str>,
        finished: bool,
    ) -> DbResult<()> {
        self.c().execute(
            "UPDATE rotations SET state = ?2, new_version = COALESCE(?3, new_version), old_ref = COALESCE(?4, old_ref), \
             revoke_after = ?5, message = ?6, finished_at = CASE WHEN ?7 THEN ?8 ELSE finished_at END WHERE id = ?1",
            params![id, state, new_version, old_ref, revoke_after, message, finished, now_ms()],
        )?;
        Ok(())
    }

    pub fn rotation_set_rotator(&self, id: i64, rotator: Option<&str>) -> DbResult<()> {
        self.c().execute("UPDATE rotations SET rotator = ?2 WHERE id = ?1", params![id, rotator])?;
        Ok(())
    }

    /// Moves a rotation to `to` only if it is still in `from` (so two
    /// actions racing on one rotation can't both apply). Returns whether it moved.
    pub fn rotation_transition(&self, id: i64, from: &str, to: &str, message: &str, finished: bool) -> DbResult<bool> {
        let n = self.c().execute(
            "UPDATE rotations SET state = ?3, message = ?4, finished_at = CASE WHEN ?5 THEN ?6 ELSE finished_at END \
             WHERE id = ?1 AND state = ?2",
            params![id, from, to, message, finished, now_ms()],
        )?;
        Ok(n > 0)
    }

    /// Pushes back a failed revocation, if the rotation is still waiting.
    pub fn rotation_retry(&self, id: i64, revoke_after: i64, message: &str) -> DbResult<()> {
        self.c().execute(
            "UPDATE rotations SET revoke_after = ?2, message = ?3 WHERE id = ?1 AND state = 'grace'",
            params![id, revoke_after, message],
        )?;
        Ok(())
    }

    /// Managing credentials are only ever owner-only.
    pub fn secret_force_owner_only(&self, name: &str) -> DbResult<()> {
        self.c().execute("UPDATE secrets SET owner_only = 1 WHERE name = ?1", [name])?;
        Ok(())
    }

    /// Whether another secret names this one as its manager.
    pub fn secret_is_parent(&self, name: &str) -> DbResult<bool> {
        self.c().prepare("SELECT 1 FROM secrets WHERE parent = ?1 LIMIT 1")?.exists([name])
    }

    pub fn rotation_get(&self, id: i64) -> DbResult<Option<RotationRow>> {
        self.c()
            .query_row(
                &format!("SELECT {ROTATION_COLS} FROM rotations r JOIN secrets s ON s.id = r.secret_id WHERE r.id = ?1"),
                [id],
                rotation_from_row,
            )
            .optional()
    }

    pub fn rotations_recent(&self, secret_id: Option<i64>, limit: i64) -> DbResult<Vec<RotationRow>> {
        let c = self.c();
        let mut st = c.prepare(&format!(
            "SELECT {ROTATION_COLS} FROM rotations r JOIN secrets s ON s.id = r.secret_id \
             WHERE ?1 IS NULL OR r.secret_id = ?1 ORDER BY r.id DESC LIMIT ?2"
        ))?;
        let rows = st.query_map(params![secret_id, limit], rotation_from_row)?;
        rows.collect()
    }

    // ---- attention acknowledgements ----

    pub fn ack_set(&self, secret_id: i64, kind: &str, fp: &str) -> DbResult<()> {
        self.c().execute(
            "INSERT INTO attention_acks(secret_id, kind, fp, acked_at) VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(secret_id, kind) DO UPDATE SET fp = excluded.fp, acked_at = excluded.acked_at",
            params![secret_id, kind, fp, now_ms()],
        )?;
        Ok(())
    }

    /// (secret_id, kind) -> (fp, acked_at)
    pub fn acks_all(&self) -> DbResult<HashMap<(i64, String), (String, i64)>> {
        let c = self.c();
        let mut st = c.prepare("SELECT secret_id, kind, fp, acked_at FROM attention_acks")?;
        let rows = st.query_map([], |r| Ok(((r.get(0)?, r.get(1)?), (r.get(2)?, r.get(3)?))))?;
        rows.collect()
    }

    pub fn acks_clear(&self, secret_id: i64) -> DbResult<usize> {
        self.c().execute("DELETE FROM attention_acks WHERE secret_id = ?1", [secret_id])
    }

    /// The newest rotation of each secret.
    pub fn rotations_latest(&self) -> DbResult<Vec<RotationRow>> {
        let c = self.c();
        let mut st = c.prepare(&format!(
            "SELECT {ROTATION_COLS} FROM rotations r JOIN secrets s ON s.id = r.secret_id \
             WHERE r.id IN (SELECT MAX(id) FROM rotations GROUP BY secret_id)"
        ))?;
        let rows = st.query_map([], rotation_from_row)?;
        rows.collect()
    }

    /// Rotations whose old key is due to be revoked.
    pub fn rotations_due(&self, now: i64) -> DbResult<Vec<RotationRow>> {
        let c = self.c();
        let mut st = c.prepare(&format!(
            "SELECT {ROTATION_COLS} FROM rotations r JOIN secrets s ON s.id = r.secret_id \
             WHERE r.state = 'grace' AND r.revoke_after <= ?1 ORDER BY r.id"
        ))?;
        let rows = st.query_map([now], rotation_from_row)?;
        rows.collect()
    }

    /// A rotation that hasn't finished: only one may run per secret.
    pub fn rotation_active(&self, secret_id: i64) -> DbResult<Option<RotationRow>> {
        self.c()
            .query_row(
                &format!(
                    "SELECT {ROTATION_COLS} FROM rotations r JOIN secrets s ON s.id = r.secret_id \
                     WHERE r.secret_id = ?1 AND r.state IN ('running', 'grace', 'manual_revoke') ORDER BY r.id DESC LIMIT 1"
                ),
                [secret_id],
                rotation_from_row,
            )
            .optional()
    }

    /// Rotations left 'running' by a crash or restart.
    pub fn rotations_fail_stale(&self) -> DbResult<usize> {
        self.c().execute(
            "UPDATE rotations SET state = 'failed', message = 'interrupted by a restart; check that this key works', \
             finished_at = ?1 WHERE state = 'running'",
            [now_ms()],
        )
    }

    #[cfg(test)]
    pub fn raw(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.c()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(action: &str) -> NewEvent {
        NewEvent {
            ts: now_ms(),
            node: "n".into(),
            user: "u".into(),
            ip: "100.64.0.1".into(),
            actor: "a".into(),
            action: action.into(),
            secret: None,
            status: 200,
            latency_us: 5,
            upstream_us: None,
            detail: None,
        }
    }

    #[test]
    fn audit_chain_detects_tampering() {
        let db = Db::memory().unwrap();
        for a in ["one", "two", "three"] {
            db.event_insert(ev(a)).unwrap();
        }
        let r = db.audit_verify().unwrap();
        assert!(r.ok && r.checked == 3);
        db.raw().execute("UPDATE events SET action = 'forged' WHERE id = 2", []).unwrap();
        let r = db.audit_verify().unwrap();
        assert!(!r.ok);
        assert_eq!(r.first_bad_id, Some(2));
    }

    #[test]
    fn audit_chain_detects_deleted_middle_row() {
        let db = Db::memory().unwrap();
        for a in ["one", "two", "three"] {
            db.event_insert(ev(a)).unwrap();
        }
        db.raw().execute("DELETE FROM events WHERE id = 2", []).unwrap();
        assert!(!db.audit_verify().unwrap().ok);
    }

    #[test]
    fn old_databases_are_migrated() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE secrets (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, notes TEXT NOT NULL DEFAULT '', \
             tags TEXT NOT NULL DEFAULT '[]', description TEXT NOT NULL DEFAULT '', provider TEXT, provider_name TEXT, \
             risk TEXT, risk_reason TEXT, facts TEXT NOT NULL DEFAULT '{}', docs_url TEXT, rotate_url TEXT, \
             describe_status TEXT NOT NULL DEFAULT 'pending', proxy_base_url TEXT, proxy_auth TEXT, \
             version INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, \
             last_used_at INTEGER, use_count INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE secret_versions (secret_id INTEGER NOT NULL, version INTEGER NOT NULL, value_ct BLOB NOT NULL, \
             dek_ct BLOB NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (secret_id, version));
             CREATE TABLE tokens (id INTEGER PRIMARY KEY, name TEXT NOT NULL, hash BLOB NOT NULL UNIQUE, scopes TEXT NOT NULL, \
             secrets TEXT NOT NULL, nodes TEXT NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER, revoked_at INTEGER);
             INSERT INTO secrets(name, version, created_at, updated_at) VALUES ('OLD', 1, 1, 1);
             INSERT INTO secret_versions VALUES (1, 1, x'00', x'00', 1);",
        )
        .unwrap();
        let db = Db::init(conn).unwrap();
        let m = db.secret_get("OLD").unwrap().unwrap();
        assert_eq!(m.kind, "api_key");
        assert!(!m.owner_only);
        assert_eq!(m.fields, serde_json::json!({}));
        assert_eq!(db.secret_ciphertext(m.id).unwrap().unwrap().format, 0);
        assert!(db.token_list().unwrap().is_empty());
    }

    #[test]
    fn versions_are_never_reused_and_current_is_protected() {
        let db = Db::memory().unwrap();
        let nv = NewValue { format: 0, parts: &[], mac: &[1; 32], provider_ref: None };
        let id = db.secret_create("A", "", &[], &Settings::default(), &nv, |_, _| Ok((vec![1; 40], vec![2; 40]))).unwrap();
        let v2 = db.secret_add_version(id, &nv, |_, v| Ok((vec![v as u8; 40], vec![2; 40]))).unwrap();
        assert_eq!(v2, 2);
        assert!(!db.version_delete(id, 2).unwrap(), "the current version can't be deleted");
        assert!(db.version_restore(id, 1).unwrap());
        assert!(db.version_delete(id, 2).unwrap());
        let v3 = db.secret_add_version(id, &nv, |_, v| Ok((vec![v as u8; 40], vec![2; 40]))).unwrap();
        assert_eq!(v3, 3, "version 2 is never reused, so old ciphertext AAD can't collide");
    }

    #[test]
    fn deleting_secret_removes_ciphertext() {
        let db = Db::memory().unwrap();
        let v = NewValue { format: 0, parts: &[], mac: &[0; 32], provider_ref: None };
        let id = db.secret_create("A", "", &[], &Settings::default(), &v, |_, _| Ok((vec![1; 40], vec![2; 40]))).unwrap();
        db.secret_delete(id).unwrap();
        let n: i64 = db.raw().query_row("SELECT COUNT(*) FROM secret_versions", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0);
    }
}
