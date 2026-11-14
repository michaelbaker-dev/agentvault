//! The macOS Keychain, for unlocking the vault after a restart.
//!
//! The vault program creates the item itself, so macOS lets only that program
//! read it without asking: another program running as the same user (an AI
//! agent's shell, `security find-generic-password`) gets a prompt on the Mac's
//! screen instead of the passphrase. The vault never shows prompts itself: if
//! the Keychain would need to ask (after an upgrade changed the program), the
//! read fails, the vault starts locked, and `agentvault auto-unlock` stores the
//! passphrase again for the new program.

use zeroize::Zeroizing;

/// The item: "AgentVault" / "auto-unlock" in the login Keychain.
#[cfg(target_os = "macos")]
const SERVICE: &str = "AgentVault";
#[cfg(target_os = "macos")]
const ACCOUNT: &str = "auto-unlock";

#[cfg(target_os = "macos")]
mod imp {
    use super::{ACCOUNT, SERVICE};
    use security_framework::os::macos::keychain::SecKeychain;
    use security_framework::passwords;
    use zeroize::Zeroizing;

    const NOT_FOUND: i32 = -25300; // errSecItemNotFound
    const NEEDS_PROMPT: i32 = -25308; // errSecInteractionNotAllowed
    const NOT_OURS: i32 = -25293; // errSecAuthFailed: the item belongs to another program
    const WRONG_OWNER: i32 = -25244; // errSecInvalidOwnerEdit

    fn explain(e: security_framework::base::Error) -> String {
        match e.code() {
            NEEDS_PROMPT => "the login Keychain is locked (macOS only opens it in your logged-in session; \
                             run this in Terminal on the Mac, not over SSH)"
                .into(),
            NOT_OURS | WRONG_OWNER => "the stored passphrase belongs to another build of agentvault. \
                                       Delete \"AgentVault\" in the Keychain Access app, then sign in on the web page"
                .into(),
            _ => e.message().unwrap_or_else(|| format!("Keychain error {}", e.code())),
        }
    }

    pub fn get() -> Result<Option<Zeroizing<String>>, String> {
        let _no_prompts = SecKeychain::disable_user_interaction().map_err(explain)?;
        match passwords::get_generic_password(SERVICE, ACCOUNT) {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                let text = std::str::from_utf8(&bytes).map_err(|_| "the stored passphrase isn't text".to_string())?;
                Ok(Some(Zeroizing::new(text.to_string())))
            }
            Err(e) if e.code() == NOT_FOUND => Ok(None),
            Err(e) => Err(explain(e)),
        }
    }

    pub fn set(passphrase: &str) -> Result<(), String> {
        // Replace rather than update, so this program becomes the item's owner.
        delete()?;
        passwords::set_generic_password(SERVICE, ACCOUNT, passphrase.as_bytes()).map_err(explain)
    }

    pub fn delete() -> Result<bool, String> {
        match passwords::delete_generic_password(SERVICE, ACCOUNT) {
            Ok(()) => Ok(true),
            Err(e) if e.code() == NOT_FOUND => Ok(false),
            Err(e) => Err(explain(e)),
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use zeroize::Zeroizing;

    pub fn get() -> Result<Option<Zeroizing<String>>, String> {
        Ok(None)
    }
    pub fn set(_: &str) -> Result<(), String> {
        Err("the Keychain is only on macOS; on Linux use sudo /usr/local/lib/agentvault/auto-unlock".into())
    }
    pub fn delete() -> Result<bool, String> {
        Ok(false)
    }
}

/// The stored boot passphrase, if there is one and this program may read it.
pub fn get() -> Result<Option<Zeroizing<String>>, String> {
    imp::get()
}

/// Stores the boot passphrase, owned by this program.
pub fn set(passphrase: &str) -> Result<(), String> {
    imp::set(passphrase)
}

/// Removes the stored boot passphrase. Ok(false) if there wasn't one.
pub fn delete() -> Result<bool, String> {
    imp::delete()
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    /// Touches the real login Keychain, so it only runs when asked:
    /// cargo test keychain -- --ignored
    #[test]
    #[ignore]
    fn stores_reads_back_and_deletes() {
        let probe = "agentvault keychain test, not a real passphrase";
        super::set(probe).expect("set");
        assert_eq!(super::get().expect("get").as_deref().map(|s| s.as_str()), Some(probe));
        assert!(super::delete().expect("delete"));
        assert!(super::get().expect("get after delete").is_none());
    }
}

/// Checks another program can't read the item silently: run `store_probe`
/// with one build, then `other_program_is_refused` with a different build,
/// then `remove_probe` with the first build. Each touches the real Keychain.
#[cfg(all(test, target_os = "macos"))]
mod cross_program {
    #[test]
    #[ignore]
    fn store_probe() {
        super::set("agentvault cross-program probe").expect("set");
    }

    #[test]
    #[ignore]
    fn other_program_is_refused() {
        let got = super::get();
        println!(
            "other program reading: {:?}",
            got.as_ref().map(|o| o.as_ref().map(|_| "<VALUE RETURNED>"))
        );
        assert!(got.is_err(), "a different program must not read the item without a prompt");
        println!("other program deleting: {:?}", super::delete());
    }

    #[test]
    #[ignore]
    fn remove_probe() {
        println!("owner deleting: {:?}", super::delete());
    }
}
