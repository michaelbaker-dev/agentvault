# keys

A secrets vault for your Tailscale network, in one Rust binary. Store API keys once, then let apps and AI agents use them over HTTPS without copying `.env` files around.

- **Web interface** for adding, editing, renaming, revealing and deleting secrets.
- **REST API** with everything the web interface does.
- **Proxy**: `/v1/proxy/NAME/...` calls the provider with the key attached on the server, so the caller never sees the key.
- **MCP endpoint** so Claude Code can find and use keys through the proxy. It has no tool that returns raw values.
- **Automatic descriptions.** When you add a key, the vault:
  - recognises the provider from the key's format;
  - asks the provider what the key can do (account, scopes);
  - has Claude write a plain-English description and risk rating from that metadata only.
- **Import**: paste a key file (a `.env` or free-form notes). The vault proposes names, recognises providers, links keys that belong together (key ID + secret, client ID + secret, login + password), skips duplicates and flags everything as exposed until replaced. Nothing is stored until you confirm.
- **Rotation**: about a third of common providers can be rotated by the vault itself through their API; the rest get a guided flow with a link to the right page and plain steps. Old keys are revoked after a grace period, and any rotation can be undone until then.
- **Owner-only secrets**: passwords and wallet keys can be hidden from every token, whatever its scopes.
- **Needs attention**: exposed, expired, rejected, overdue or incomplete keys, most urgent first.
- **Dashboard**: which secret was used, how many times, from which machine, with p50/p95/p99 latency for the vault and for providers.
- **Tamper-evident audit log**: every request is hash-chained.

## Security model

| Layer | What it does |
|---|---|
| Network | Binds only to the Tailscale IP. Rejects foreign `Host` headers (DNS rebinding) and cross-origin browser requests. |
| Device identity | Every request is attributed to a tailnet device and user via tailscaled, which WireGuard authenticates and which can't be spoofed. |
| Credential | Every request also needs a scoped token or the owner's web session. Device identity alone isn't enough, because an AI agent on your laptop shares the laptop's identity. |
| Tokens | Scopes (`list`, `read`, `write`, `delete`, `proxy`), secret-name patterns (`OPENAI_*`), optional machine pinning. Only the SHA-256 is stored, and tokens are revocable instantly. |
| Web session | Owner's devices only. The passphrase is required. The cookie is `HttpOnly; Secure; SameSite=Strict`, bound to the device's stable Tailscale node ID, and every call also needs a CSRF header. Sessions expire after 15 min idle or 12 h total. |
| Step-up | Revealing or copying a value, creating a token, deleting, and changing a proxy target all need the passphrase entered in the last 5 minutes. A cookie stolen by an agent running as you can list secrets, but can't take them. |
| Encryption | Passphrase → Argon2id (64 MiB) → key-encryption key → root key → a fresh XChaCha20-Poly1305 data key per value version. Each ciphertext is bound to its secret id and version. The root key lives only in memory. **Lock** wipes it. |
| Proxy | Only the owner can change where a key is sent. Paths can't escape the provider's base URL. Only GET/POST/PUT/PATCH/DELETE are forwarded (TRACE would echo the key). The key is redacted from response bodies and headers, whether it comes back raw, base64-encoded or URL-encoded. Tokens can be limited to GET, so an agent can read through a key but can't mint new keys or change settings at the provider. Redirects aren't followed. |
| Process | Not dumpable (no core dumps, and same-user processes can't read its memory). Runs as its own system user under a strict systemd sandbox. |
| Brute force | 5 passphrase attempts per device per 15 minutes, counted before the check runs, so parallel guesses don't help. Argon2 attempts are capped at 2 concurrent. |
| Owner-only | Secrets marked "only me" (passwords and wallet keys start that way) don't exist as far as tokens are concerned: not listed, not readable, not usable through the proxy or MCP, and not named in duplicate warnings. |
| Owner settings | Only the owner can change who may see a secret, its linked plaintext fields, its provider, its manager, its rotation schedule or its proxy target. Exposing an owner-only secret, changing a manager or proxy, importing, rotating and undoing a rotation all need a fresh passphrase. |
| Rotation | A key set as another's manager becomes owner-only, and rotation refuses a manager that isn't owner-only or isn't the expected kind. Tokens can't change the value of a key that rotates, renews itself or manages another, so they can't steer which key the vault creates or revokes. A rotation stops before creating anything if the old key isn't in the manager's account. Managing credentials go only to their provider's fixed API address; IDs from provider replies are checked before they go into a URL; provider error text is redacted before it's logged or shown. Revocation and undo re-check the rotation under a per-key lock and never touch a key that changed since. A rotation that fails leaves the old key in place (a Cloudflare roll, which replaces the value at once, keeps the new value). |
| Import | Pasted text is parsed in memory. The preview shows only a public prefix and the length of each value; the values stay on the server for 30 minutes for the one device that pasted them, and are used up by the commit. |
| Duplicates | Detected with a fingerprint keyed by the vault's root key, so the database can't be used to test password guesses. |

Not covered:
- **Root access.** Someone with root on the vault machine while it's unlocked.
- **Misuse within a token's scopes.** A non-GET-only `proxy` token can do anything the key can do at the provider. It just can't take the key with it.
- **Names of owner-only secrets.** A token trying to create a secret under a name that an owner-only secret already uses gets "already exists".
- **Clearing the audit log.** It is hash-chained but not keyed, so someone who can write the database file can rewrite it end to end, or drop the newest rows, without detection. To keep a record off the machine, periodically export the head hash shown on the Settings page.

## Install (on the vault machine)

```sh
cargo build --release
sudo tailscale set --operator=$USER   # optional; lets you run `tailscale cert` without sudo
sudo deploy/install.sh
```

The installer:
- creates a `keys` system user;
- installs the binary and `/etc/keys/config.toml` (listening on this machine's Tailscale IP, port 443);
- fetches a real certificate with `tailscale cert`;
- starts the service and a weekly certificate-refresh timer.

Then open `https://<machine>.<tailnet>.ts.net` on one of your devices and choose a passphrase.

**The passphrase is the only way to decrypt the vault. Keep a copy offline.** Back up `/var/lib/keys/data/keys.db`. It is safe to copy because values inside it are encrypted, but it's useless without the passphrase.

### Unlocking after a reboot

The vault's key lives only in memory, so after a restart it starts **locked**: apps get `503` until it's unlocked. The installer asks whether it should unlock itself. To turn that on (or off) later:

```sh
sudo /usr/local/lib/keys/auto-unlock        # asks for your passphrase, restarts the vault, checks it unlocked
sudo /usr/local/lib/keys/auto-unlock off    # back to signing in after each restart
```

The passphrase is stored as an encrypted systemd credential (`/etc/keys/passphrase.cred`). If the passphrase you type doesn't unlock the vault, the script puts everything back as it was. **Settings** shows whether automatic unlock is on. If you change your passphrase, the Secrets page warns you until you run the script again.

This machine has no TPM, so the credential is protected by a root-only host key. Anyone with root on this machine can unlock the vault. That's the price of starting unattended.

## Import your keys

Open **Import**, paste the file (or choose it), click **Preview**, check the names and fill in anything marked "Also needs", then **Import selected**. Or see what would happen first, without a server:

```sh
keys import-preview keys.txt     # every value masked; nothing stored or sent
```

Then delete the file everywhere it exists (`shred -u keys.txt`) and replace the exposed keys from the **Rotation** page.

## Rotation

Rotating means swapping a key for a new one so a copy that leaked stops working. Apps calling providers through the proxy switch over instantly; apps that fetched the raw value have `grace_hours` (24 by default) to fetch it again before the old key is revoked. Every rotation can be undone until then.

| Provider | How | What the vault needs |
|---|---|---|
| OpenRouter keys | Automatic | An OpenRouter **management key** ([create one](https://openrouter.ai/settings/management-keys)) stored in the vault and set as the key's manager. The vault creates the new key with the same spending limit and deletes the old one. |
| Cloudflare tokens | Automatic (roll) | A token allowed to roll tokens: create one from the "Create additional tokens" template at [API Tokens](https://dash.cloudflare.com/profile/api-tokens), store it, set it as manager. A token that has that permission itself can roll without one. The old value stops working at once. |
| Tailscale auth keys | Automatic | A Tailscale **OAuth client** with the `auth_keys` scope and a tag ([trust credentials](https://console.tailscale.com/admin/settings/trust-credentials)), stored with its `client_id` field and set as manager. The new key copies the old one's tags. |
| Microsoft Entra (Azure) client secrets | Automatic | The secret's `tenant_id` and `client_id` fields, and the app must be allowed to manage itself: grant it `Application.ReadWrite.OwnedBy` and make its service principal an owner of the application (a one-time admin step). |
| Google API keys | Automatic | A **service account** JSON key with the API Keys Admin role (`roles/serviceusage.apiKeysAdmin`) on the project, stored and set as manager. The new key keeps the old one's restrictions. |
| Anthropic keys | Guided, old key disabled automatically | Anthropic has no API to create keys. Create one at [platform.claude.com/settings/keys](https://platform.claude.com/settings/keys) and paste it. With an Anthropic **Admin key** as manager, the vault disables the old key after the grace period. |
| GitHub | Renews itself | Use a **GitHub App** instead of a personal token: store its private key with `app_id` and `installation_id`. Apps get installation tokens that expire after an hour. |
| Slack | Renews itself | Turn on token rotation for the Slack app (this can't be turned off), then store the refresh token with `client_id` and a `client_secret` part. Bot tokens are refreshed every 12 hours. |
| Tailscale API | Renews itself | Store an OAuth client instead of an API key; the proxy uses hour-long tokens. |
| Everything else | Guided | The **Rotate** button shows the steps and opens the provider's key page. Paste the new key; the vault checks it with the provider, switches over and reminds you to delete the old one. |
| Wallet keys | Can't be rotated | Move the funds to a new wallet. |

Keys due by their schedule are rotated by the scheduler when the vault is unlocked and `scheduled = true`.

## Use it

Create a token on the **Tokens** page. Pick the narrowest preset that works.

```sh
# an app that needs the raw value
curl -s -H "Authorization: Bearer kt_..." https://HOST/v1/secrets/DB_PASSWORD/value

# call a provider without ever holding its key
curl -s -H "Authorization: Bearer kt_..." https://HOST/v1/proxy/OPENAI_API_KEY/v1/models

```

### From Claude: MCP, a skill, or both

Make a token with the preset **Claude / agents** (list + proxy, GET-only), tied to the machine Claude runs on. Then, in your own terminal:

```sh
ln -s "$PWD/skill/keys-vault" ~/.claude/skills/keys-vault   # the skill (once per machine)
~/.claude/skills/keys-vault/scripts/keys setup               # asks for the token without showing it, checks it, saves it, connects MCP
```

Restart Claude Code afterwards. `setup` connects both routes:

| | Claude sees the token? | Works in |
|---|---|---|
| **MCP** | No: it stays in Claude Code's settings, and Claude only gets list, describe and proxy tools | Claude Code, Claude Desktop, any MCP client |
| **Skill + helper** | It could read `~/.config/keys/token`, so keep that token to list + proxy on one machine, where it can't reveal any key | Anything with a shell |

The skill (`skill/keys-vault/`) teaches Claude good habits whichever route is connected:
- use the vault instead of asking you for keys;
- prefer the proxy;
- keep keys out of code, `.env` files and commits;
- make apps fetch keys at runtime.

It also brings a helper, `skill/keys-vault/scripts/keys` (Python, standard library only), which works on its own too:

```sh
keys setup                                     # address + token, checked; connects MCP (--no-mcp to skip)
keys check                                     # reachable, unlocked, token works?
keys list [word]                               # keys this token may use; no values
keys describe GITHUB_TOKEN                     # what it's for, risk, proxy address
keys call GITHUB_TOKEN /user                   # call the provider through the vault
keys run OPENAI_API_KEY -- python app.py       # program gets the key; output has it blanked (needs read scope)
```

### REST API

| Method | Path | Scope |
|---|---|---|
| GET | `/v1/secrets` | list |
| POST | `/v1/secrets` `{name, value, notes?, tags?, verify?}` | write |
| GET | `/v1/secrets/NAME` | list |
| PATCH | `/v1/secrets/NAME` `{name?, value?, notes?, tags?}` (`proxy` is owner-only) | write |
| DELETE | `/v1/secrets/NAME` | delete |
| GET | `/v1/secrets/NAME/value` | read |
| POST | `/v1/secrets/NAME/describe` | write |
| ANY | `/v1/proxy/NAME/PATH` | proxy |
| POST | `/mcp` | list / proxy |
| GET | `/v1/dashboard?range=24h\|7d\|30d`, `/v1/events`, `/v1/audit/verify`, `/v1/tokens` | owner session |
| POST | `/v1/tokens` `{name, scopes, secrets?, nodes?, proxy_get_only?}` | owner session |
| PATCH | `/v1/tokens/ID` (same fields; takes effect on the token's next request) | owner session |
| DELETE | `/v1/tokens/ID` (revoke) | owner session |
| POST | `/v1/secrets/NAME/rotate` `{}` (automatic) or `{value, fields?, extras?, skip_check?}` (by hand) | owner session |
| GET | `/v1/rotations`, `/v1/attention`, `/v1/providers` | owner session |
| POST | `/v1/attention/dismiss` `{secret}` (OK: hide its current items until something changes), `/v1/attention/restore` `{secret}` | owner session |
| POST | `/v1/rotations/ID/rollback`, `/v1/rotations/ID/done` | owner session |
| POST | `/v1/import/preview` `{text}`, `/v1/import/commit` `{import_id, items}` | owner session |

Secrets made of several parts carry `extras: [{name, value}]` (encrypted) and `fields: {name: value}` (plaintext, owner-only to change). The proxy can send them with `basic:<field>` or `headers:Name={part};Other={value}`.

**Claude descriptions:** add your Anthropic key as `ANTHROPIC_API_KEY`. From then on, each new key's description is written by Claude (`claude-opus-5-5` at low effort, with server-side refusal fallback). Claude receives only:
- the name and your notes;
- the detected provider;
- what the provider reported about the key.

It never receives the value.

## Checking that it's right

```sh
cargo test                       # 77 tests: crypto, auth, tokens, CSRF, sealing, MCP, audit chain, import, every rotator against a fake provider
cargo audit && cargo deny check  # RustSec advisories, licenses, sources
cargo clippy --all-targets -- -D warnings
gitleaks dir . && trufflehog filesystem src web
keys audit-verify -c /etc/keys/config.toml   # hash chain intact?
```

After a week of use, scan your own machines for keys that should now live only in the vault:

```sh
trufflehog filesystem ~ --only-verified
```
