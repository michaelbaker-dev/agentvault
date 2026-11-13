# Changelog

## 0.1.0 (unreleased)

### spandeck integration

- Stations connect with the owner's approval: `POST /v1/token-requests`, an approval page that opens as a pop-up and closes itself, and a one-time collection from the machine that asked. Issued tokens are list + proxy only, read-only by default, pinned to the machine's stable Tailscale ID and blind to owner-only keys; approving again replaces a station's token.
- `/v1/status` says `"service":"agentvault"` and tells callers other than the owner only the version and whether the vault is set up and unlocked.
- `X-AgentVault-Actor` on proxy calls is recorded as a reported label and stripped before the provider call.
- Optional station token rotation: `POST /v1/tokens/self/rotate` and `PUT /v1/tokens/self/rotation`, with the old token valid until the new one's first use (24-hour cap), overdue tokens allowed only to rotate, and `token_replaced` / `token_rotated` / `token_overdue` error codes.
- `POST /v1/attention/report`: values seen in transcripts are matched after an identical reply and land on Needs attention.
- The Tokens page shows each token's rotation.

### Security review (November 2026)

Fixed before the first release, each with a regression test:
- The web session now needs a recent passphrase to use keys through the proxy (REST and MCP), add or change a value, rename, or preview an import, so a stolen cookie can't drive owner-only keys or test password guesses.
- Editing a key's notes or name can no longer change its detected provider (and so where the proxy sends it).
- Secret ids are never reused, and minted access tokens are dropped when a key is deleted or its provider or fields change.
- Machine-pinned tokens remember the device's stable Tailscale ID on first use.
- A token no longer learns the name of an owner-only manager from rotation status.
- Import hides passwords in labels ("pass", "pin", `user:password`, mixed letters and digits) from notes and suggested names; one import is capped at 500 keys.
- The proxy strips `Range` and method-override headers, refuses compressed replies, and redacts more encodings of an echoed key.
- The TLS certificate moved to root-owned `/etc/agentvault/tls`, so the root-run refresh script can't be tricked through symlinks.
- `agentvault-cli`: Claude Code's MCP connection gets the token from a header helper (never on a command line or in its settings); `run` redacts across the whole output stream, multi-line keys and encoded forms; the token is only sent to an https `*.ts.net` vault or the saved address.
- Copied secrets are cleared from the clipboard after 45 seconds.
- CI: actions pinned to commit SHAs, no persisted credentials, least-privilege release jobs, a verified gitleaks download, and signed build provenance for releases.


First public version, as AgentVault (developed under the working name "keys").

- Encrypted vault (Argon2id + XChaCha20-Poly1305) reachable only over Tailscale, with a web interface, REST API, MCP endpoint and key-attaching proxy.
- Provider recognition and checks for 48 providers, with optional descriptions written by Claude from metadata only.
- Import from `.env` files or free-form notes, with a masked preview, duplicate detection and owner-only passwords and wallet keys.
- Rotation:
  - automatic for OpenRouter, Cloudflare, Tailscale auth keys, Azure client secrets and Google API keys;
  - self-renewing tokens for GitHub Apps, Tailscale OAuth and Slack;
  - guided, with links, for everything else;
  - a grace period and undo.
- Scoped tokens (key patterns, machine pinning, GET-only proxy) that can be edited in place.
- A "Needs attention" list that you can OK until the situation changes.
- Dashboard of usage and latency; hash-chained audit log.
- Installer with prerequisite checks, systemd hardening, Tailscale certificates and verified automatic unlock; uninstaller.
- `agentvault` Claude skill and `agentvault-cli` helper.
