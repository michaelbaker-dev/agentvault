# Roadmap

What's planned next for AgentVault, in order. Each step ships with tests, README updates and a CHANGELOG entry.

| Step | What | Status |
|---|---|---|
| 1 | spandeck integration, phase 1: connecting a station | Done, tested live with spandeck |
| 2 | spandeck integration, phase 2: station token rotation | Done, tested live with spandeck |
| 3 | spandeck integration, phase 3: exposed-key reports | Done, tested live with spandeck |
| 4 | First release, v0.1.0 | Waiting: the repository stays private for now. Then: make it public, turn on private vulnerability reporting, tag `v0.1.0` (ARM builds need a public repository) |
| 5 | Mac version | Mostly done: runs, installs and unlocks itself on Apple silicon; Mac downloads and other Tailscale editions left |
| 6 | Moving the vault | Planned |
| 7 | Hot standby | Planned |
| 8 | Machine accounts and an SSH agent | Idea, to come back to |

Smaller improvements land as they come up; see the CHANGELOG.

## 1–3. spandeck integration (done)

The contract, decisions and task lists are agreed with the spandeck project and kept there. In short:

- **Phase 1:**
  - `/v1/status` identifies the vault (`"service":"agentvault"`) and shows non-owners only version and lock state.
  - A station asks for a token, the owner approves it on the vault's own page, which opens as a small pop-up window from spandeck's Control Deck, shows the vault's address and closes itself. The station collects the token once. The vault is never embedded in another page, so its address is always visible where the passphrase is typed.
  - Requests are accepted only from the owner's devices and tagged machines.
  - Tokens are list + proxy only, read-only by default, pinned to the station's stable Tailscale ID, never see owner-only keys, and never expire by default.
  - A label header (`X-AgentVault-Actor`) is recorded and stripped before the provider call.
- **Phase 2** (rotation is hygiene: a pinned token is useless anywhere but its machine, so "never" is the default):
  - The rotation setting lives only in spandeck's Control Deck: Never, or every 1 hour or more. There's no passphrase and no other page; spandeckd reports it with `PUT /v1/tokens/self/rotation`, and the vault logs every change.
  - `POST /v1/tokens/self/rotate` swaps a station token for a fresh one, from its own machine only, and is allowed even when the token is overdue (an overdue token can do nothing else).
  - The old token keeps working until the new one is first used, 24 hours at most, so a crash before spandeckd saves the new token can't lock the station out. Swapping again with the old token discards the unused new one.
  - spandeck alerts the owner when the vault's setting differs from the Control Deck's, or when someone else swapped the station's token.
- **Phase 3:** `POST /v1/attention/report` takes a value seen in a transcript, matches it, discards it and always gives the same reply.

## 5. Mac version

Same code and repository. Built and tested on an Apple silicon Mac (macOS 26) with the standalone Tailscale app.

| Part | Linux | Mac | State |
|---|---|---|---|
| Service | systemd, a dedicated system user | A launchd agent for the owner's own (admin) account, in their login session; no sudo to install | Done |
| Unlock at boot | systemd credential | Login Keychain item owned by the vault program, stored at the next web sign-in; upgrades re-arm with one sign-in | Done |
| Device identity | tailscaled's LocalAPI socket | Standalone app: localhost port + same-user-proof file; App Store app: group container; open-source `tailscaled`: socket | Standalone tested; App Store and `tailscaled` written, untested |
| HTTPS certificate | `tailscale cert`, refreshed by a timer | The vault runs `tailscale cert` itself every 6 hours | Done |
| Port | 443 | 9443 or the next free port (a normal account can't use 443) | Done |
| Process hardening | `prctl` (no dumps), systemd sandbox | `PT_DENY_ATTACH`, no core dumps | Done |
| Install | `install.sh`, `uninstall.sh` | `deploy/macos/install.sh`, `uninstall.sh` | Done; shellcheck in CI |
| Downloads | x86_64 and ARM64 Linux | Apple silicon, built on the owner's build Mac rather than paid CI runners | To do, with the first release |

Still open:
- test the App Store app and the open-source `tailscaled`;
- spandeck looks for a vault on port 443 only; it needs to accept a port in the vault's address (to agree in the shared doc);
- log rotation for `~/Library/Logs/AgentVault`.

## 6. Moving the vault

A tested procedure, and a command for it:

1. On the old machine, lock the vault and take a backup. The database is encrypted, so the copy is safe to move.
2. On the new machine, install, restore the backup and sign in with the same passphrase. The installer writes the new Tailscale address into the config.
3. Station and app tokens keep working, because they're tied to the callers' machines, not the vault's. spandeck rediscovers the vault. Apps and Claude's helper need the new address, or the backup address from step 7.
4. Remove the old install with `uninstall.sh --purge`.

Automatic unlock is set up again on the new machine. The credential is bound to the machine, so it can't be copied.

## 7. Hot standby

One vault is in charge at any time. A standby on a second machine keeps things working if the primary goes down.

| Piece | Design |
|---|---|
| Copying data | The standby keeps a continuously updated copy of the encrypted database, pulled from the primary over the tailnet. Useless without the passphrase. |
| Primary down | The standby switches to **reduced mode** on its own: listing keys and calls through the proxy keep working; nothing changes (no rotations, no new tokens, no edits). Two vaults can never both act. |
| Becoming primary | The owner promotes the standby on its own page, with the passphrase, once the old primary is known to be gone. Then it does everything. The old primary must not come back as primary: on start it sees it was replaced and becomes the standby. |
| Finding it | spandeck uses whichever vault answers. Apps and Claude's helper get an optional backup address and try it when the primary doesn't answer. |
| Rotation safety | Rotations happen only on the primary. The 24-hour grace period covers a standby that is a little behind. |
| Trade-off | The standby must unlock itself, so its machine also holds the stored passphrase: a second machine where root access means vault access. |

Fully automatic promotion is deliberately left out: if the network splits, both machines would think they are in charge and could revoke each other's new keys. Revisit only with a proper way to decide which side wins.

Open:
- the replication mechanism (vault-to-vault pull over the tailnet, or shipping the database's write-ahead log);
- how long the primary must be gone before reduced mode starts;
- how the usage log written on a standby is merged back.

## 8. Machine accounts and an SSH agent

An idea to come back to, from setting up the build Mac.

- **Machine passwords** (a Mac's admin password, a server's root password) already fit the vault's password type: owner-only by default, revealed or copied from the web page, never seen by agents.
- **Agents that need root** should get narrow sudo rules on each machine (named commands, no password), not an admin password. Handing an agent the password through `agentvault-cli run` works, but gives it full admin rights; the vault would only add a log line and a revoke button.
- **The vault as an SSH agent:** it keeps SSH private keys and signs logins on request over the tailnet, like 1Password's SSH agent. The key never leaves the vault, every login is logged and limited by token, and revoking a token cuts access at once. Tailscale SSH (access decided by tailnet rules, no keys) is the alternative for machines on the tailnet.

