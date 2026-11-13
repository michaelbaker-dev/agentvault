//! What gets encrypted for one version of a secret: the main value plus,
//! for credentials that only work as a set, extra secret parts (an OAuth
//! client secret next to its refresh token, say). Non-secret parts such as a
//! client ID or account email live in plaintext metadata instead.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Format 0: the value's UTF-8 bytes. Format 1: JSON with extras.
pub const FORMAT_RAW: i64 = 0;
pub const FORMAT_JSON: i64 = 1;

pub const MAX_EXTRAS: usize = 8;

#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct Extra {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Default, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct Material {
    pub value: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extras: Vec<Extra>,
}

pub fn valid_part_name(n: &str) -> bool {
    (1..=40).contains(&n.len())
        && n.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && n != "value"
}

impl Material {
    pub fn single(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            extras: vec![],
        }
    }

    /// Serialises for encryption. Returns (format, bytes).
    pub fn encode(&self) -> (i64, Zeroizing<Vec<u8>>) {
        if self.extras.is_empty() {
            return (FORMAT_RAW, Zeroizing::new(self.value.as_bytes().to_vec()));
        }
        let mut buf = Zeroizing::new(Vec::with_capacity(self.value.len() * 2 + 256));
        serde_json::to_writer(&mut *buf, self).expect("json");
        (FORMAT_JSON, buf)
    }

    pub fn decode(format: i64, bytes: &[u8]) -> Result<Self, &'static str> {
        match format {
            FORMAT_RAW => Ok(Self::single(std::str::from_utf8(bytes).map_err(|_| "value is not UTF-8")?)),
            FORMAT_JSON => serde_json::from_slice(bytes).map_err(|_| "unreadable value"),
            _ => Err("unknown value format"),
        }
    }

    /// A secret part by name: `value` or one of the extras.
    pub fn get(&self, name: &str) -> Option<&str> {
        if name == "value" {
            return Some(&self.value);
        }
        self.extras.iter().find(|e| e.name == name).map(|e| e.value.as_str())
    }

    pub fn set_extra(&mut self, name: &str, value: String) {
        match self.extras.iter_mut().find(|e| e.name == name) {
            Some(e) => e.value = value,
            None => self.extras.push(Extra { name: name.into(), value }),
        }
    }

    pub fn extra_names(&self) -> Vec<String> {
        self.extras.iter().map(|e| e.name.clone()).collect()
    }

    /// Every secret string, for redaction.
    pub fn secrets(&self) -> Vec<&str> {
        std::iter::once(self.value.as_str())
            .chain(self.extras.iter().map(|e| e.value.as_str()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_both_formats() {
        let m = Material::single("abc");
        let (f, b) = m.encode();
        assert_eq!(f, FORMAT_RAW);
        assert_eq!(&b[..], b"abc");
        assert_eq!(Material::decode(f, &b).unwrap().value, "abc");

        let mut m = Material::single("refresh-token");
        m.set_extra("client_secret", "cs".into());
        let (f, b) = m.encode();
        assert_eq!(f, FORMAT_JSON);
        let back = Material::decode(f, &b).unwrap();
        assert_eq!(back.get("value"), Some("refresh-token"));
        assert_eq!(back.get("client_secret"), Some("cs"));
        assert_eq!(back.get("nope"), None);
        assert_eq!(back.secrets(), vec!["refresh-token", "cs"]);
    }

    #[test]
    fn part_names() {
        assert!(valid_part_name("client_secret"));
        assert!(!valid_part_name("value"));
        assert!(!valid_part_name("Client"));
        assert!(!valid_part_name("a-b"));
        assert!(!valid_part_name(""));
    }
}
