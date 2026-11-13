//! Key hierarchy:
//!
//! passphrase --Argon2id--> KEK --wraps--> root key --wraps--> per-version data key --encrypts--> value
//!
//! The root key exists only in memory while the vault is unsealed. Every
//! ciphertext is bound (via AAD) to its secret id and version, so rows can't be
//! swapped between secrets.

use std::sync::{Mutex, RwLock};
use zeroize::Zeroizing;

use crate::crypto::{self, KdfParams, KeyBytes};
use crate::db::Db;

const ROOT_AAD: &[u8] = b"keys/root/v1";

#[derive(Debug)]
pub enum VaultError {
    NotInitialized,
    AlreadyInitialized,
    Sealed,
    BadPassphrase,
    Corrupt(&'static str),
    Db(rusqlite::Error),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInitialized => f.write_str("vault has not been set up yet"),
            Self::AlreadyInitialized => f.write_str("vault is already set up"),
            Self::Sealed => f.write_str("vault is sealed: sign in to the web interface to unlock it"),
            Self::BadPassphrase => f.write_str("wrong passphrase"),
            Self::Corrupt(what) => write!(f, "vault data is corrupt: {what}"),
            Self::Db(e) => write!(f, "database error: {e}"),
        }
    }
}

impl From<rusqlite::Error> for VaultError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Db(e)
    }
}

#[derive(Default)]
pub struct Vault {
    root: RwLock<Option<KeyBytes>>,
    /// Serialises setup so two concurrent requests can't both initialise.
    init_lock: Mutex<()>,
}

/// Format 0 (a plain value) keeps the original AAD; other formats bind the
/// format too, so flipping it in the database makes decryption fail instead
/// of handing the whole JSON envelope to the proxy as the key.
fn value_aad(id: i64, version: i64, format: i64) -> Vec<u8> {
    if format == 0 {
        format!("keys/value/v1/{id}/{version}").into_bytes()
    } else {
        format!("keys/value/v2/{id}/{version}/f{format}").into_bytes()
    }
}
fn dek_aad(id: i64, version: i64) -> Vec<u8> {
    format!("keys/dek/v1/{id}/{version}").into_bytes()
}

fn to_key(bytes: &[u8]) -> Result<KeyBytes, VaultError> {
    let arr: [u8; crypto::KEY_LEN] = bytes.try_into().map_err(|_| VaultError::Corrupt("key length"))?;
    Ok(Zeroizing::new(arr))
}

impl Vault {
    pub fn is_initialized(db: &Db) -> Result<bool, VaultError> {
        Ok(db.meta_get("root_wrapped")?.is_some())
    }

    pub fn is_sealed(&self) -> bool {
        self.root.read().unwrap_or_else(|p| p.into_inner()).is_none()
    }

    /// Creates a new root key, wraps it with the passphrase and unseals.
    pub fn initialize(&self, db: &Db, passphrase: &str, params: KdfParams) -> Result<(), VaultError> {
        let _guard = self.init_lock.lock().unwrap_or_else(|p| p.into_inner());
        if Self::is_initialized(db)? {
            return Err(VaultError::AlreadyInitialized);
        }
        let salt: [u8; 16] = crypto::random_bytes();
        let kek = crypto::derive_kek(passphrase.as_bytes(), &salt, params).map_err(|_| VaultError::Corrupt("kdf"))?;
        let root = crypto::random_key();
        let wrapped = crypto::seal(&kek, ROOT_AAD, root.as_ref());
        let params_json = serde_json::to_vec(&params).expect("json");
        db.meta_set_many(&[("kdf", &params_json), ("salt", &salt), ("root_wrapped", &wrapped)])?;
        *self.root.write().unwrap_or_else(|p| p.into_inner()) = Some(root);
        Ok(())
    }

    /// Derives the KEK and unwraps the root key. Slow on purpose (Argon2id).
    fn unwrap_root(db: &Db, passphrase: &str) -> Result<KeyBytes, VaultError> {
        let params: KdfParams = db
            .meta_get("kdf")?
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or(VaultError::NotInitialized)?;
        let salt = db.meta_get("salt")?.ok_or(VaultError::Corrupt("salt"))?;
        let wrapped = db.meta_get("root_wrapped")?.ok_or(VaultError::NotInitialized)?;
        let kek = crypto::derive_kek(passphrase.as_bytes(), &salt, params).map_err(|_| VaultError::Corrupt("kdf"))?;
        let root = crypto::open(&kek, ROOT_AAD, &wrapped).map_err(|_| VaultError::BadPassphrase)?;
        to_key(&root)
    }

    /// Checks the passphrase and, if sealed, unseals.
    pub fn unlock(&self, db: &Db, passphrase: &str) -> Result<(), VaultError> {
        let root = Self::unwrap_root(db, passphrase)?;
        let mut guard = self.root.write().unwrap_or_else(|p| p.into_inner());
        if guard.is_none() {
            *guard = Some(root);
        }
        Ok(())
    }

    pub fn seal(&self) {
        // Dropping the Zeroizing wrapper wipes the key bytes.
        *self.root.write().unwrap_or_else(|p| p.into_inner()) = None;
    }

    pub fn change_passphrase(&self, db: &Db, current: &str, new: &str, params: KdfParams) -> Result<(), VaultError> {
        let root = Self::unwrap_root(db, current)?;
        let salt: [u8; 16] = crypto::random_bytes();
        let kek = crypto::derive_kek(new.as_bytes(), &salt, params).map_err(|_| VaultError::Corrupt("kdf"))?;
        let wrapped = crypto::seal(&kek, ROOT_AAD, root.as_ref());
        let params_json = serde_json::to_vec(&params).expect("json");
        db.meta_set_many(&[("kdf", &params_json), ("salt", &salt), ("root_wrapped", &wrapped)])?;
        Ok(())
    }

    fn with_root<T>(&self, f: impl FnOnce(&[u8; crypto::KEY_LEN]) -> Result<T, VaultError>) -> Result<T, VaultError> {
        let guard = self.root.read().unwrap_or_else(|p| p.into_inner());
        let root = guard.as_ref().ok_or(VaultError::Sealed)?;
        f(root)
    }

    /// Encrypts a value under a fresh data key. Returns (value ciphertext, wrapped data key).
    pub fn encrypt(&self, id: i64, version: i64, format: i64, value: &[u8]) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
        self.with_root(|root| {
            let dek = crypto::random_key();
            let value_ct = crypto::seal(&dek, &value_aad(id, version, format), value);
            let dek_ct = crypto::seal(root, &dek_aad(id, version), dek.as_ref());
            Ok((value_ct, dek_ct))
        })
    }

    pub fn decrypt(&self, id: i64, version: i64, format: i64, value_ct: &[u8], dek_ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        self.with_root(|root| {
            let dek = crypto::open(root, &dek_aad(id, version), dek_ct).map_err(|_| VaultError::Corrupt("data key"))?;
            let dek = to_key(&dek)?;
            crypto::open(&dek, &value_aad(id, version, format), value_ct).map_err(|_| VaultError::Corrupt("value"))
        })
    }

    /// Fingerprint for spotting the same value stored twice. Keyed by the root
    /// key, so a stolen database can't be used to test password guesses.
    pub fn fingerprint(&self, value: &[u8]) -> Result<[u8; 32], VaultError> {
        self.with_root(|root| {
            let k = Zeroizing::new(crypto::hmac_sha256(root, b"keys/fingerprint/v1"));
            Ok(crypto::hmac_sha256(k.as_ref(), value))
        })
    }

    pub fn ensure_unsealed(&self) -> Result<(), VaultError> {
        if self.is_sealed() { Err(VaultError::Sealed) } else { Ok(()) }
    }
}

#[cfg(test)]
pub const TEST_KDF: KdfParams = KdfParams {
    m_cost_kib: 256,
    t_cost: 1,
    p_cost: 1,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle() {
        let db = Db::memory().unwrap();
        let v = Vault::default();
        assert!(v.is_sealed());
        v.initialize(&db, "correct horse battery", TEST_KDF).unwrap();
        assert!(matches!(v.initialize(&db, "x", TEST_KDF), Err(VaultError::AlreadyInitialized)));

        let (ct, dek) = v.encrypt(7, 1, 0, b"sk-live-123").unwrap();
        assert_eq!(&v.decrypt(7, 1, 0, &ct, &dek).unwrap()[..], b"sk-live-123");
        assert!(v.decrypt(8, 1, 0, &ct, &dek).is_err(), "ciphertext is bound to its secret id");
        assert!(v.decrypt(7, 2, 0, &ct, &dek).is_err(), "and to its version");
        assert!(v.decrypt(7, 1, 1, &ct, &dek).is_err(), "and to its format");
        let (ct1, dek1) = v.encrypt(7, 1, 1, b"{}").unwrap();
        assert!(
            v.decrypt(7, 1, 0, &ct1, &dek1).is_err(),
            "a JSON value can't be read back as a plain one"
        );

        v.seal();
        assert!(matches!(v.decrypt(7, 1, 0, &ct, &dek), Err(VaultError::Sealed)));
        assert!(matches!(v.unlock(&db, "wrong"), Err(VaultError::BadPassphrase)));
        v.unlock(&db, "correct horse battery").unwrap();
        assert_eq!(&v.decrypt(7, 1, 0, &ct, &dek).unwrap()[..], b"sk-live-123");

        let f = v.fingerprint(b"pw").unwrap();
        assert_eq!(f, v.fingerprint(b"pw").unwrap());
        assert_ne!(f, v.fingerprint(b"pw2").unwrap());
        assert_ne!(f, crate::crypto::sha256(b"pw"), "keyed, not a plain hash");

        v.change_passphrase(&db, "correct horse battery", "new passphrase here", TEST_KDF)
            .unwrap();
        v.seal();
        assert!(v.unlock(&db, "correct horse battery").is_err());
        v.unlock(&db, "new passphrase here").unwrap();
        assert_eq!(&v.decrypt(7, 1, 0, &ct, &dek).unwrap()[..], b"sk-live-123");
    }
}
