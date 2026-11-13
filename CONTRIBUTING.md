# Contributing

Thanks for helping. Bug reports, provider additions and fixes are all welcome.

## Before you start

- **Security problems:** report them privately, as described in [SECURITY.md](SECURITY.md), not in an issue.
- **Bigger changes:** open an issue first to agree on the approach.
- **Never put real keys in an issue, a test or a commit.** Tests build fake values at runtime, such as `format!("ghp_{}", "A".repeat(36))`, so secret scanners stay quiet and nothing real can leak.

## Building and testing

You need Rust 1.89 or newer and a C compiler.

```sh
cargo build
cargo test
cargo fmt --check && cargo clippy --all-targets -- -D warnings
cargo deny check
```

CI runs the same checks, plus the minimum Rust version, shellcheck on the installer scripts and gitleaks on the history.

To try the web interface, run a test vault on another port. Create a config like `config.example.toml` with `listen = "<your tailscale ip>:8443"`, its own `data_dir`, and a self-signed certificate. Then run `cargo run -- serve -c that-config.toml` and open `https://<machine>.<tailnet>.ts.net:8443`.

## Where things live

| Path | What it is |
|---|---|
| `src/vault.rs`, `src/crypto.rs` | Key hierarchy and encryption |
| `src/server.rs`, `src/auth.rs` | HTTP API, sessions, tokens |
| `src/proxy.rs` | The key-attaching proxy and redaction |
| `src/mcp.rs` | The MCP endpoint |
| `src/providers.rs` | Provider recognition, checks and rotation settings |
| `src/rotate.rs` | Rotation, renewal and the "needs attention" list |
| `src/import.rs`, `src/import_api.rs` | Parsing key files and the import flow |
| `src/tests.rs` | Integration tests, including a fake provider server for every rotator |
| `web/` | The web interface (plain JavaScript, no build step) |
| `deploy/` | Installer, uninstaller, systemd units, automatic unlock |
| `skill/keys-vault/` | The Claude skill and the `keys-cli` helper |

## Adding a provider

Add an entry to `PROVIDERS` in `src/providers.rs` with:
- the key's format;
- the API address and how it authenticates;
- a "who am I" check if the provider has one;
- the rotation mode and the link to the provider's key page.

Then add a recognition test. For an automatic rotator, add a fake of the provider's API to `src/tests.rs` and a test that runs a full rotation and undo against it.

## Pull requests

- Keep each pull request to one change, with tests.
- Update the README and `CHANGELOG.md` when behaviour changes.
- By contributing you agree that your work is dual-licensed under MIT and Apache-2.0, like the rest of the project.
