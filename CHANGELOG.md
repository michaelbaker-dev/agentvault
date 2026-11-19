# Changelog

## Unreleased

- **Streamed replies through the proxy arrive as they're sent.** The proxy used to hold back roughly a key's length at the end of every chunk, in case a key was split across two, so on a stream that stays open (server-sent events, hosted MCP servers) each event waited for the next one. It now holds back only bytes that could be the start of a key.
- **Event streams aren't cut off when they go quiet.** A reply that is a server-sent event stream stays open as long as the caller keeps it; other replies still end after 3 minutes without data, and a provider still has 3 minutes to start its reply.

- Anthropic keys starting `sk-ant-usr-` (106 characters) are recognised as Anthropic API keys, alongside `sk-ant-api03-`.
- Google API keys get a provider check: listing Gemini models (free, read-only). A key Google doesn't know shows as rejected; one that's real but not allowed to use Gemini (restricted in Google Cloud, or the API isn't enabled) shows as restricted. Google's "API key not valid" answer (HTTP 400) now counts as rejected for any provider.
- The key form's Details section names Service first, and Settings says where to find it.
- **Describe … keys with Claude** in Settings: Claude describes every key that still has a built-in description, such as keys added before your Anthropic key was in the vault (`POST /v1/describe-all`).
- **Weekly provider checks:** each key is checked with its provider again once a week (three a minute at most), so a key that was revoked, expired or ran out of credit shows under Needs attention on its own. A changed result gets a fresh description; the check doesn't count as a use of the key.
- Settings no longer says Claude is on when the key named for it isn't an Anthropic API key (for example one cut short when pasted); it says why, and the Secrets page does too. The describer checks the key's value itself, so a key pasted again works at once.
- An Anthropic key in a format the vault doesn't recognise yet can still power Claude descriptions once you set its **Service** to Anthropic API key: your choice counts, and Settings says how.
- Describing a key again without asking its provider keeps the provider's last answer instead of dropping it.
- The Mac download can be signed with a Developer ID and notarized by Apple (see docs/releasing.md): it then opens even when downloaded in a browser, and automatic unlock survives upgrades. Without the signing secrets it stays ad-hoc signed, as before.
- The Mac installer keeps the stored passphrase on upgrade when the old and new program carry the same Developer ID signature, and only asks for a sign-in after upgrades between other builds.

## 0.1.1 (2026-11-14)

- Downloads for Macs with Apple silicon (`agentvault-aarch64-macos.tar.gz`), built by GitHub with signed build provenance like the Linux ones. Unpack it and run `./install.sh`; see "On a Mac" in the README.
- The release workflow can be run by hand to build the downloads for testing without releasing them.

## 0.1.0 (2026-11-14)

### macOS

- The vault builds and runs on macOS (tested on Apple silicon, macOS 26): `deploy/macos/install.sh` installs it as a launchd agent for your account (no sudo), on port 9443 or the next free one; `deploy/macos/uninstall.sh [--purge]` removes it.
- Caller identity through the Mac Tailscale apps' local API (a localhost port with a same-user-proof password), found afresh on each call; `agentvault whois ADDRESS` checks it.
- Automatic unlock through the login Keychain: the vault stores the passphrase at your next sign-in, owns the item so other programs get a prompt instead, and follows passphrase changes. Upgrades have the old program remove its item; sign in once to store it again. `agentvault auto-unlock -c CONFIG [--off | --at-next-sign-in]`.
- Debuggers are refused with `PT_DENY_ATTACH` (Linux keeps `PR_SET_DUMPABLE`).

### Since the first helper changes

- `agentvault-cli call ... -o FILE` saves the whole reply (`-o -` writes it to stdout for a pipe); shown replies still stop at 100 KB and now say how to get the rest. MCP `proxy_request` keeps its 100 KB limit, which protects the agent's context, and a cut reply now carries a `truncated_note` saying how to get all of it.
- `github-push` sends text files inside each commit's tree request (about two requests per commit instead of one per file; a 183-file push went from 71 s to 9 s), waits and retries when GitHub asks to slow down, and carries on from a push into an empty repository that stopped partway.
- Proxied replies carry a `Server-Timing` header (`agentvault` and `provider` durations); MCP results include `timing_ms`; `agentvault-cli call` shows both.
- New key type **UniFi console API key (local)**, told apart from Site Manager keys by words in the name (network API, protect, console, UDM...). It isn't checked against Ubiquiti's cloud, so local keys no longer show as rejected.
- `agentvault-cli setup --project [NAME]`: a token used only in one project's folder (helper and that project's Claude Code), so the log shows each project and each can be revoked alone.

### Helper

- `agentvault-cli github-push OWNER/REPO` pushes a branch to GitHub through the vault's proxy: no SSH key or git credentials on the machine, and the key never leaves the vault. Commits are recreated exactly and checked; fast-forward only; works on empty repositories. The skill and the MCP server's instructions point agents to it.

### Fixes

- The helper followed redirects with the vault token attached, so a GitHub CI log request sent it to the log's storage server. It now never follows a redirect with the token, and fetches download links with no credentials.
- MCP `proxy_request` follows a GET's redirect to a download link itself, with no key, over HTTPS to public addresses only; any other redirect returns its address (unless it contains the key).
- The proxy no longer forwards the vault's own `x-agentvault-*` headers to providers.

### Web page

- Each key's card shows its own warnings (exposed, rejected, overdue and so on) with **OK** and **Restore**, not only the Needs attention list.
- Revoked tokens can be taken off the Tokens list, one at a time or all at once. Active tokens must be revoked first; every removal is logged.

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
