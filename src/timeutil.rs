//! Just enough date handling for the expiry times providers report.

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// days_from_civil).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn num(s: &str) -> Option<i64> {
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

/// Inverse of [`days_from_civil`].
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// `YYYY-MM-DD` (UTC) for a time in milliseconds.
pub fn format_date(ms: i64) -> String {
    let (y, m, d) = civil_from_days(ms.div_euclid(86_400_000));
    format!("{y:04}-{m:02}-{d:02}")
}

/// RFC 3339 (UTC, whole seconds) for a time in milliseconds.
pub fn format_rfc3339(ms: i64) -> String {
    let secs = ms.div_euclid(1000).rem_euclid(86_400);
    format!("{}T{:02}:{:02}:{:02}Z", format_date(ms), secs / 3600, secs / 60 % 60, secs % 60)
}

/// Parses `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)`, the same with
/// a space or ` UTC`, or Unix seconds. Returns milliseconds since the epoch.
pub fn parse_time(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Some(n) = num(s) {
        // Seconds, unless it is clearly already milliseconds.
        return Some(if n > 100_000_000_000 { n } else { n * 1000 });
    }
    if s.len() < 10 {
        return None;
    }
    let (date, rest) = s.split_at(10);
    let mut dp = date.split('-');
    let (y, m, d) = (num(dp.next()?)?, num(dp.next()?)?, num(dp.next()?)?);
    if dp.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let mut ms = days_from_civil(y, m, d) * 86_400_000;
    let rest = rest.trim_start_matches(['T', 't', ' ']);
    if rest.is_empty() {
        return Some(ms);
    }
    if rest.len() < 8 {
        return None;
    }
    let (time, mut zone) = rest.split_at(8);
    let mut tp = time.split(':');
    let (h, mi, sec) = (num(tp.next()?)?, num(tp.next()?)?, num(tp.next()?)?);
    if h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    ms += (h * 3600 + mi * 60 + sec) * 1000;
    if let Some(frac) = zone.strip_prefix('.') {
        let digits = frac.bytes().take_while(u8::is_ascii_digit).count();
        zone = &frac[digits..];
    }
    let zone = zone.trim();
    let offset_min = match zone {
        "" | "Z" | "z" | "UTC" | "GMT" | "+00:00" => 0,
        z if (z.starts_with('+') || z.starts_with('-')) && z.len() == 6 && &z[3..4] == ":" => {
            let sign = if z.starts_with('-') { -1 } else { 1 };
            sign * (num(&z[1..3])? * 60 + num(&z[4..6])?)
        }
        _ => return None,
    };
    Some(ms - offset_min * 60_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(parse_time("1970-01-01"), Some(0));
        assert_eq!(parse_time("2000-03-01T00:00:00Z"), Some(951_868_800_000));
        assert_eq!(parse_time("2026-10-19T12:00:00.123456Z"), parse_time("2026-10-19T12:00:00Z"));
        assert_eq!(parse_time("2026-10-19T14:00:00+02:00"), parse_time("2026-10-19T12:00:00Z"));
        assert_eq!(parse_time("2026-10-19 12:00:00 UTC"), parse_time("2026-10-19T12:00:00Z"));
        assert_eq!(parse_time("1760875200"), Some(1_760_875_200_000));
        assert_eq!(parse_time("nope"), None);
        assert_eq!(parse_time("2026-13-01"), None);
        assert_eq!(parse_time("2026-10-19T12:00:00+0200"), None);
        for t in [0, 951_868_800_000, 1_760_875_200_000, 4_102_444_800_000] {
            assert_eq!(parse_time(&format_rfc3339(t)), Some(t));
        }
        assert_eq!(format_date(1_760_875_200_000), "2025-10-19");
    }
}
