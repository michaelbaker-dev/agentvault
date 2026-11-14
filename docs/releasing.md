# Releasing

Pushing a tag such as `v0.1.2` runs [the release workflow](../.github/workflows/release.yml). It builds and tests the Linux (x86_64, ARM64) and Mac (Apple silicon) downloads, records signed build provenance for each, and attaches them to a GitHub release whose notes are that version's section of the [CHANGELOG](../CHANGELOG.md).

To test the downloads first, run the workflow by hand (**Actions → Release → Run workflow**). It builds everything and keeps the archives as workflow artifacts, without releasing.

Before tagging:
1. Set `version` in `Cargo.toml` and run `cargo build` so `Cargo.lock` follows.
2. Give the version its own section in the CHANGELOG, with the date.
3. Wait for CI to pass on that commit.

## Signing the Mac download

Without the secrets below, the Mac build is ad-hoc signed and the workflow says so. It still works when downloaded with `curl`. With them, it is signed with a Developer ID, uses the hardened runtime and is notarized by Apple. That brings two benefits:
- macOS opens it even when it's downloaded in a browser;
- automatic unlock survives upgrades, because the Keychain trusts every build signed by the same team, not one exact file.

Setting it up takes an Apple Developer Program membership. Do it once, on your Mac, and never paste any of these values into a chat or an issue.

1. **The certificate.** In Xcode, open **Settings → Accounts**, choose your team, then **Manage Certificates → + → Developer ID Application**. Only the team's Account Holder can create one.
2. **Export it.** In Keychain Access, under **My Certificates**, right-click **Developer ID Application: …** and choose **Export**. Save it as a `.p12` file with a strong password. The export includes the private key; keep the file safe.
3. **A notary key.** In [App Store Connect](https://appstoreconnect.apple.com/access/integrations/api), open **Users and Access → Integrations → App Store Connect API → Team Keys** and generate a key with the **Developer** role. Note its **Key ID** and the **Issuer ID** shown above the list, and download the `AuthKey_….p8` file. Apple lets you download it only once.
4. **A GitHub environment for the secrets.** On the repository, open **Settings → Environments → New environment** and name it `release`. Under **Deployment branches and tags**, choose **Selected branches and tags** and add `main` and the tag pattern `v*`, so no other branch can use the secrets.
5. **The secrets.** Add these to the `release` environment:

   | Secret | Value |
   |---|---|
   | `MACOS_CERT_P12` | The `.p12` file in base64. `base64 -i DeveloperID.p12 \| pbcopy` copies it; paste it in. |
   | `MACOS_CERT_PASSWORD` | The `.p12` file's password |
   | `NOTARY_KEY_P8` | The whole text of `AuthKey_….p8`. `pbcopy < AuthKey_XXXX.p8` copies it. |
   | `NOTARY_KEY_ID` | The key's Key ID |
   | `NOTARY_ISSUER_ID` | The Issuer ID |

6. **Clean up.** Store the `.p12`, its password and the `.p8` in your vault as owner-only secrets, then delete the files.

Then run the workflow by hand. The Mac build's log shows the signature (`designated => anchor apple generic and identifier "com.agentvault" …`) and Apple's verdict (`"status": "Accepted"`).

**Who can use the secrets.** Workflows running in the `release` environment, from `main` or a `v*` tag, which means anyone who can push to the repository. Revoke the certificate in your Apple developer account and the key in App Store Connect if you ever suspect they leaked.
