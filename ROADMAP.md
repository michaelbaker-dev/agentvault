# Roadmap

What's planned next for AgentVault, in order. Each step ships with tests, README updates and a CHANGELOG entry.

| Step | What | Why |
|---|---|---|
| 1 | spandeck integration, phase 1: connecting a station | Agents in spandeck panes use keys through the vault without holding them |
| 2 | spandeck integration, phase 2: station token rotation | Optional rotation set per station in spandeck's Control Deck, fully automatic |
| 3 | Mac version | The vault runs on a Mac as well as Linux |
| 4 | Moving the vault | Put the vault on another machine without losing keys, tokens or settings |
| 5 | Hot standby | Agents and apps keep working when the vault's machine goes down |
| 6 | spandeck integration, phase 3: exposed-key reports | A key spandeck finds in a transcript lands on Needs attention |
| 7 | spandeck integration, phase 4: approvals inside the Control Deck | Approving a station without leaving the Control Deck |

## 1, 2, 6 and 7. spandeck integration

The contract, decisions and task lists are agreed with the spandeck project and kept there. In short:

- **Phase 1:**
  - `/v1/status` identifies the vault (`"service":"agentvault"`) and shows non-owners only version and lock state.
  - A station asks for a token, the owner approves it on the vault's own page with the passphrase, and the station collects it once.
  - Requests are accepted only from the owner's devices and tagged machines.
  - Tokens are list + proxy only, read-only by default, pinned to the station's stable Tailscale ID, never see owner-only keys, and never expire by default.
  - A label header (`X-AgentVault-Actor`) is recorded and stripped before the provider call.
- **Phase 2** (rotation is hygiene: a pinned token is useless anywhere but its machine, so "never" is the default):
  - The rotation setting lives only in spandeck's Control Deck: Never, or every 1 hour or more. There's no passphrase and no other page; spandeckd reports it with `PUT /v1/tokens/self/rotation`, and the vault logs every change.
  - `POST /v1/tokens/self/rotate` swaps a station token for a fresh one, from its own machine only, and is allowed even when the token is overdue (an overdue token can do nothing else).
  - The old token keeps working until the new one is first used, 24 hours at most, so a crash before spandeckd saves the new token can't lock the station out. Swapping again with the old token discards the unused new one.
  - spandeck alerts the owner when the vault's setting differs from the Control Deck's, or when someone else swapped the station's token.
- **Phase 3:** `POST /v1/attention/report` takes a value seen in a transcript, matches it, discards it and always gives the same reply.
- **Phase 4:** the approval page can be shown as a panel embedded in the Control Deck. The vault allows exactly the Control Deck's address to embed it and refuses every other site; its sign-in has to work inside the panel without weakening the protection against forged requests. The passphrase is still typed only into the vault's own panel.

## 3. Mac version

Same code and repository, released alongside the Linux builds.

| Part | Linux today | Mac |
|---|---|---|
| Service | systemd units | launchd job (`/Library/LaunchDaemons`) |
| Unlock at boot | systemd credential | macOS Keychain item readable only by the service |
| Device identity | tailscaled's LocalAPI socket | Each Mac Tailscale edition (App Store, standalone, open-source `tailscaled`) exposes LocalAPI differently: detect which is installed, support all three |
| HTTPS certificate | `tailscale cert`, refreshed weekly by a timer | The same command, refreshed by launchd |
| Process hardening | `prctl` (no dumps), systemd sandbox | `PT_DENY_ATTACH`, no core dumps, a dedicated service user |
| Install | `install.sh`, `uninstall.sh` | Mac versions of both, with the same prerequisite checks |
| Downloads | x86_64 and ARM64 Linux | Apple Silicon and Intel, built and tested in CI on macOS runners |

Open: whether the Keychain item can be read at boot before anyone logs in (decides between the System keychain and a root-only file), and which Tailscale editions to test on.

## 4. Moving the vault

A tested procedure, and a command for it:

1. On the old machine, lock the vault and take a backup. The database is encrypted, so the copy is safe to move.
2. On the new machine, install, restore the backup and sign in with the same passphrase. The installer writes the new Tailscale address into the config.
3. Station and app tokens keep working, because they're tied to the callers' machines, not the vault's. spandeck rediscovers the vault. Apps and Claude's helper need the new address, or the backup address from step 5.
4. Remove the old install with `uninstall.sh --purge`.

Automatic unlock is set up again on the new machine. The credential is bound to the machine, so it can't be copied.

## 5. Hot standby

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
