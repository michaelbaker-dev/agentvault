//! Thin wrappers over audited RustCrypto primitives. Nothing here invents
//! cryptography: XChaCha20-Poly1305 for encryption, Argon2id for passphrases.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

pub type KeyBytes = Zeroizing<[u8; KEY_LEN]>;

#[derive(Debug)]
pub struct CryptoError;

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("decryption failed")
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("OS random number generator failed");
    buf
}

pub fn random_key() -> KeyBytes {
    Zeroizing::new(random_bytes())
}

/// Encrypts `plaintext` under `key` with a fresh random nonce, binding `aad`.
/// Output layout: nonce (24) || ciphertext || tag (16).
pub fn seal(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    let nonce_bytes: [u8; NONCE_LEN] = random_bytes();
    let nonce = XNonce::from(nonce_bytes);
    let ct = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .expect("XChaCha20-Poly1305 encryption cannot fail for in-memory input");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    out
}

/// Reverses [`seal`]. Fails if the key, the AAD or any byte of `sealed` differs.
pub fn open(key: &[u8; KEY_LEN], aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError);
    }
    let (nonce_bytes, ct) = sealed.split_at(NONCE_LEN);
    let nonce_arr: [u8; NONCE_LEN] = nonce_bytes.try_into().map_err(|_| CryptoError)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    cipher
        .decrypt(&XNonce::from(nonce_arr), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| CryptoError)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// OWASP-recommended Argon2id settings: 64 MiB, 3 passes.
    pub const DEFAULT: Self = Self { m_cost_kib: 64 * 1024, t_cost: 3, p_cost: 1 };
}

/// Derives a key-encryption key from the passphrase with Argon2id.
pub fn derive_kek(passphrase: &[u8], salt: &[u8], p: KdfParams) -> Result<KeyBytes, CryptoError> {
    let params = argon2::Params::new(p.m_cost_kib, p.t_cost, p.p_cost, Some(KEY_LEN)).map_err(|_| CryptoError)?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon.hash_password_into(passphrase, salt, out.as_mut()).map_err(|_| CryptoError)?;
    Ok(out)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = Zeroizing::new([0u8; BLOCK]);
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(data);
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let k = random_key();
        let sealed = seal(&k, b"aad", b"hello");
        assert_eq!(&open(&k, b"aad", &sealed).unwrap()[..], b"hello");
    }

    #[test]
    fn wrong_aad_or_key_or_tamper_fails() {
        let k = random_key();
        let mut sealed = seal(&k, b"secret/1/1", b"value");
        assert!(open(&k, b"secret/2/1", &sealed).is_err(), "AAD must bind ciphertext to its row");
        assert!(open(&random_key(), b"secret/1/1", &sealed).is_err());
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(open(&k, b"secret/1/1", &sealed).is_err());
        assert!(open(&k, b"", &[0u8; 10]).is_err());
    }

    #[test]
    fn hmac_matches_rfc4231() {
        // RFC 4231 test cases 1 and 2.
        assert_eq!(
            hex::encode(hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Case 6: key longer than the block size.
        assert_eq!(
            hex::encode(hmac_sha256(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First")),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn nonces_are_fresh() {
        let k = random_key();
        assert_ne!(seal(&k, b"", b"x"), seal(&k, b"", b"x"));
    }

    #[test]
    fn kdf_is_deterministic_and_salted() {
        let p = KdfParams { m_cost_kib: 256, t_cost: 1, p_cost: 1 };
        let a = derive_kek(b"pw", b"saltsaltsaltsalt", p).unwrap();
        let b = derive_kek(b"pw", b"saltsaltsaltsalt", p).unwrap();
        let c = derive_kek(b"pw", b"othersaltothersa", p).unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
    }
}
