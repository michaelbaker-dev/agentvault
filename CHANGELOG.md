# Changelog

## 0.1.0 (unreleased)

First public version.

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
- `keys-vault` Claude skill and `keys-cli` helper.
