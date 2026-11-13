//! Aggregates usage events for the dashboard.

use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::db::{EventRow, now_ms};

#[derive(Debug, Clone, Copy)]
pub struct Range {
    pub label: &'static str,
    pub span_ms: i64,
    pub bucket_ms: i64,
}

const HOUR: i64 = 3_600_000;

impl Range {
    pub fn parse(s: &str) -> Self {
        match s {
            "7d" => Range { label: "7d", span_ms: 7 * 24 * HOUR, bucket_ms: 6 * HOUR },
            "30d" => Range { label: "30d", span_ms: 30 * 24 * HOUR, bucket_ms: 24 * HOUR },
            _ => Range { label: "24h", span_ms: 24 * HOUR, bucket_ms: HOUR },
        }
    }
}

#[derive(Serialize)]
pub struct Dashboard {
    pub range: &'static str,
    pub from: i64,
    pub to: i64,
    pub bucket_ms: i64,
    pub totals: Totals,
    pub timeline: Vec<Bucket>,
    pub by_secret: Vec<SecretUsage>,
    pub by_machine: Vec<MachineUsage>,
    pub latency: Vec<LatencyRow>,
    pub upstream: Vec<LatencyRow>,
    pub recent: Vec<EventRow>,
    pub truncated: bool,
}

#[derive(Serialize, Default)]
pub struct Totals {
    pub requests: u64,
    pub errors: u64,
    pub denied: u64,
    pub machines: u64,
    pub secrets_used: u64,
    pub p95_ms: f64,
}

#[derive(Serialize, Clone, Default)]
pub struct Bucket {
    pub t: i64,
    pub ok: u64,
    pub errors: u64,
}

#[derive(Serialize)]
pub struct SecretUsage {
    pub secret: String,
    pub count: u64,
    pub machines: Vec<String>,
    pub actions: BTreeMap<String, u64>,
    pub last_used: i64,
}

#[derive(Serialize)]
pub struct MachineUsage {
    pub node: String,
    pub user: String,
    pub count: u64,
    pub secrets: u64,
    pub denied: u64,
    pub last_seen: i64,
}

#[derive(Serialize)]
pub struct LatencyRow {
    pub key: String,
    pub count: u64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
}

/// Nearest-rank percentile over sorted microsecond samples, in milliseconds.
fn pct(sorted: &[i64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil().max(1.0) as usize;
    let us = sorted[rank.min(sorted.len()) - 1];
    (us as f64 / 1000.0 * 100.0).round() / 100.0
}

fn latency_rows(groups: HashMap<String, Vec<i64>>) -> Vec<LatencyRow> {
    let mut rows: Vec<LatencyRow> = groups
        .into_iter()
        .map(|(key, mut v)| {
            v.sort_unstable();
            LatencyRow {
                key,
                count: v.len() as u64,
                p50_ms: pct(&v, 50.0),
                p95_ms: pct(&v, 95.0),
                p99_ms: pct(&v, 99.0),
                max_ms: pct(&v, 100.0),
            }
        })
        .collect();
    rows.sort_by(|a, b| b.count.cmp(&a.count).then(a.key.cmp(&b.key)));
    rows
}

/// The vault refused the request. A provider rejecting a key (a 401 on a proxy
/// or verify call) is a failure, not a denial.
pub fn is_denied(e: &EventRow) -> bool {
    e.action == "denied"
        || e.detail.as_deref().is_some_and(|d| d.contains("denied"))
        || (matches!(e.action.as_str(), "login" | "vault.setup") && matches!(e.status, 401 | 403 | 429))
}

pub const EVENT_LIMIT: i64 = 200_000;

pub fn build(range: Range, events: Vec<EventRow>) -> Dashboard {
    let to = now_ms();
    let from = to - range.span_ms;
    let truncated = events.len() as i64 >= EVENT_LIMIT;
    let n_buckets = (range.span_ms / range.bucket_ms) as usize;
    let first_bucket = (from / range.bucket_ms + 1) * range.bucket_ms - range.bucket_ms;
    let mut timeline: Vec<Bucket> =
        (0..=n_buckets).map(|i| Bucket { t: first_bucket + i as i64 * range.bucket_ms, ..Default::default() }).collect();

    let mut totals = Totals::default();
    let mut machines: HashMap<(String, String), MachineUsage> = HashMap::new();
    let mut machine_secrets: HashMap<(String, String), HashSet<String>> = HashMap::new();
    let mut secrets: HashMap<String, SecretUsage> = HashMap::new();
    let mut by_action: HashMap<String, Vec<i64>> = HashMap::new();
    let mut by_upstream: HashMap<String, Vec<i64>> = HashMap::new();
    let mut all_latency = Vec::with_capacity(events.len());

    for e in &events {
        totals.requests += 1;
        let denied = is_denied(e);
        let error = e.status >= 400;
        if denied {
            totals.denied += 1;
        }
        if error {
            totals.errors += 1;
        }
        let idx = ((e.ts - first_bucket) / range.bucket_ms).clamp(0, n_buckets as i64) as usize;
        if error {
            timeline[idx].errors += 1;
        } else {
            timeline[idx].ok += 1;
        }

        let mk = (e.node.clone(), e.user.clone());
        let m = machines.entry(mk.clone()).or_insert_with(|| MachineUsage {
            node: e.node.clone(),
            user: e.user.clone(),
            count: 0,
            secrets: 0,
            denied: 0,
            last_seen: 0,
        });
        m.count += 1;
        m.last_seen = m.last_seen.max(e.ts);
        if denied {
            m.denied += 1;
        }

        if let Some(s) = &e.secret {
            machine_secrets.entry(mk).or_default().insert(s.clone());
            let su = secrets.entry(s.clone()).or_insert_with(|| SecretUsage {
                secret: s.clone(),
                count: 0,
                machines: vec![],
                actions: BTreeMap::new(),
                last_used: 0,
            });
            su.count += 1;
            su.last_used = su.last_used.max(e.ts);
            *su.actions.entry(e.action.clone()).or_default() += 1;
            if !su.machines.contains(&e.node) {
                su.machines.push(e.node.clone());
            }
        }

        by_action.entry(e.action.clone()).or_default().push(e.latency_us);
        all_latency.push(e.latency_us);
        if let (Some(u), Some(s)) = (e.upstream_us, &e.secret) {
            by_upstream.entry(s.clone()).or_default().push(u);
        }
    }

    for (k, set) in machine_secrets {
        if let Some(m) = machines.get_mut(&k) {
            m.secrets = set.len() as u64;
        }
    }
    all_latency.sort_unstable();
    totals.p95_ms = pct(&all_latency, 95.0);
    totals.machines = machines.len() as u64;
    totals.secrets_used = secrets.len() as u64;

    let mut by_secret: Vec<SecretUsage> = secrets.into_values().collect();
    by_secret.sort_by(|a, b| b.count.cmp(&a.count).then(a.secret.cmp(&b.secret)));
    let mut by_machine: Vec<MachineUsage> = machines.into_values().collect();
    by_machine.sort_by(|a, b| b.count.cmp(&a.count).then(a.node.cmp(&b.node)));

    let recent: Vec<EventRow> = events.iter().rev().take(50).cloned().collect();

    Dashboard {
        range: range.label,
        from,
        to,
        bucket_ms: range.bucket_ms,
        totals,
        timeline,
        by_secret,
        by_machine,
        latency: latency_rows(by_action),
        upstream: latency_rows(by_upstream),
        recent,
        truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(node: &str, action: &str, secret: Option<&str>, status: i64, us: i64) -> EventRow {
        EventRow {
            id: 0,
            ts: now_ms() - 1000,
            node: node.into(),
            user: "u".into(),
            ip: "100.64.0.1".into(),
            actor: "a".into(),
            action: action.into(),
            secret: secret.map(String::from),
            status,
            latency_us: us,
            upstream_us: (action == "proxy").then_some(us / 2),
            detail: None,
        }
    }

    #[test]
    fn percentiles() {
        let v: Vec<i64> = (1..=100).map(|x| x * 1000).collect();
        assert_eq!(pct(&v, 50.0), 50.0);
        assert_eq!(pct(&v, 95.0), 95.0);
        assert_eq!(pct(&v, 99.0), 99.0);
        assert_eq!(pct(&v, 100.0), 100.0);
        assert_eq!(pct(&[], 50.0), 0.0);
    }

    #[test]
    fn aggregates() {
        let d = build(
            Range::parse("24h"),
            vec![
                ev("mac", "proxy", Some("OPENAI"), 200, 4000),
                ev("mac", "secret.read", Some("OPENAI"), 200, 1000),
                ev("server", "proxy", Some("GITHUB"), 200, 2000),
                ev("server", "denied", None, 403, 100),
            ],
        );
        assert_eq!(d.totals.requests, 4);
        assert_eq!(d.totals.denied, 1);
        assert_eq!(d.totals.machines, 2);
        assert_eq!(d.totals.secrets_used, 2);
        assert_eq!(d.by_secret[0].secret, "OPENAI");
        assert_eq!(d.by_secret[0].count, 2);
        assert_eq!(d.by_machine.iter().find(|m| m.node == "mac").unwrap().secrets, 1);
        assert_eq!(d.timeline.iter().map(|b| b.ok + b.errors).sum::<u64>(), 4);
        assert_eq!(d.upstream.len(), 2);
    }
}
