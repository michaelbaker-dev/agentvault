# Roadmap

What's planned next for AgentVault, in order. Each step ships with tests, README updates and a CHANGELOG entry.

| Step | What | Status |
|---|---|---|
| 1 | spandeck integration, phase 1: connecting a station | Done, tested live with spandeck |
| 2 | spandeck integration, phase 2: station token rotation | Done, tested live with spandeck |
| 3 | spandeck integration, phase 3: exposed-key reports | Done, tested live with spandeck |
| 4 | First release, v0.1.0 | Done: Linux downloads (x86_64 and ARM64) with signed build provenance |
| 5 | Mac version | Mostly done: runs, installs and unlocks itself on Apple silicon; Mac downloads and other Tailscale editions left |
| 6 | Moving the vault | Planned |
| 7 | Standby vault at a second site, with automatic takeover | Designed, to come back to |
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

## 7. Standby vault at a second site, with automatic takeover

Designed, not started. One vault runs at each site (each on its own internet connection), so an outage at one site doesn't take the vault away. Exactly one vault is in charge at any time; the other is a standby.

### Decisions

- **Placement:** the primary at the main site, the standby at the second site, and a small **witness** in a third place (a cloud machine), so that losing one site never takes two of the three votes with it.
- **Two machines can't elect a leader safely on their own.** When the standby stops hearing from the primary, it can't tell "the primary is down" from "the link between us is down"; if it took over in the second case, both would act. A third vote settles it, as in MongoDB's arbiter, repmgr's witness, Patroni with etcd, or LiteFS and Litestream with a lease.
- **The witness holds nothing secret:** no keys and no data, only who is in charge, the current election number and the latest change number. The worst a compromised witness can do is vote for both sides; the master-only rules below still keep dangerous changes from happening twice.
- **No automatic switch back.** After an outage the new primary stays in charge until the owner switches back on its page (or an optional rule like "after an hour of stable internet"), so a flaky connection can't make the sites trade places.
- **Fail safe, never split.** When no side has two votes, both run in island mode and wait. The owner is the backup vote: the standby's page offers "Take over" with the passphrase once the owner confirms the other site is really gone.
- **Ruled out:** Tailscale Services (one address for several machines: hosts must be tagged, and callers arrive through Tailscale's proxy so the vault can't tell which device is calling); LiteFS (Linux only, needs Consul); full Raft such as openraft or rqlite (puts a full copy of the vault on the witness and is much more code; worth it only with three or more data machines).

### Design

| Piece | Design |
|---|---|
| Staying in sync | The standby asks the primary for new changes about once a second; that request is also the heartbeat. Keys, versions and tokens go across as numbered changes, still encrypted. The usage log only grows and each entry records which machine wrote it, so both sides' logs merge. |
| Who the vaults talk to | Each vault checks that the caller is the other vault's machine (Tailscale) and that it unlocked the same vault (a proof derived from the vault key). The link has its own encryption on top of HTTPS. |
| No lost changes | While the standby is up, a change counts as saved only once the standby has it. Changes are rare and made by the owner, so the extra delay doesn't matter. |
| Who's in charge | The primary holds a 10-second lease, renewed every 2 seconds with two of the three votes. If it can't renew, it switches itself to island mode before the standby may take over. The standby asks for votes only after the lease has run out, and the witness votes only for a vault that has every confirmed change (Raft's rule). Leases are measured as durations, not clock times. Taking over takes about 15 seconds. |
| Fencing | Every change and sync message carries the election number. Anything from an older number is refused, so a returning old primary sees it was replaced and becomes the standby. |
| Island mode (the side without the votes) | Keeps working on its own network: listing keys, calls through the proxy, revoking tokens, approving new station and app tokens, OKs on warnings, adding a new key. Waits for the master: changing a key's value, deleting a key, rotations, passphrase and settings. |
| Merging after an outage | The returning side sends what it recorded in island mode: usage (keep all), last-used times (take the latest), revocations (a revoke always wins), new tokens (unique, no clash), new keys (a clashing name is renamed and flagged). Then it pulls what it missed. Anything that needs a decision shows on the web page with buttons. |
| Rotation safety | Rotations run only on a primary with plenty of lease left. The 24-hour grace period covers a standby that is a little behind. |
| Finding a vault | Claude's helper, the MCP server and spandeck get both addresses, prefer the one at their own site and fall back to the other. Either vault answers; a standby passes changes on to the primary. |
| Unlocking the standby | The second site is the likelier place for a machine to be stolen, so the standby doesn't keep the whole passphrase. After a restart it asks the primary for the other half of its unlock key (like Clevis/Tang for disks). A stolen machine removed from the tailnet can never unlock. Cost: if it restarts while the primary is down, it stays locked until the primary is back or the owner signs in. The primary keeps its own automatic unlock. |

### Failures

| What fails | Result |
|---|---|
| Main site's internet | The standby takes over with the witness's vote. The main site's vault drops to island mode for machines on its own network. |
| Second site's internet | The primary stays in charge; the standby runs in island mode. |
| Only the link between the sites | The primary keeps its lease through the witness; the standby can't win a vote. |
| The witness | Nothing changes day to day (the two vaults are two of three votes), but there's no automatic takeover until it's back: if a site also fails, both sides run in island mode. The page shows a warning. |
| The witness loses its saved state | It refuses to vote until the current primary gives it the latest election and change numbers, so it can never vote twice in one election. Replacing a witness is done on the primary's page. |

### Network checklist

- A backup internet connection at each site (e.g. the gateway switching to a cellular backup) removes the most common failure.
- Battery backup (UPS) for each vault machine, the modem and the router.
- Different local address ranges at each site.
- Key expiry turned off on both vault machines and the witness. Tailscale keeps existing connections working when the internet is down, but a device that hasn't talked to the vault recently may not find it, so the vault keeps in touch with its own machines.

### Order

1. Sync, island mode and both addresses for clients. Safe on its own, no witness needed; covers most outages for agents.
2. The witness and automatic takeover.
3. Optional: three witnesses in different places (five votes, three to win), so takeover still happens with a witness down. Two witnesses would be worse than one.

### Open

- The machine at the second site (a Raspberry Pi or small Linux box is enough; a Mac mini also works).
- Where the witness runs: a small cloud server on the tailnet, or a Cloudflare Durable Object reached over the internet with a key only the two vaults hold (check pricing first).

## 8. Machine accounts and an SSH agent

An idea to come back to, from setting up the build Mac.

- **Machine passwords** (a Mac's admin password, a server's root password) already fit the vault's password type: owner-only by default, revealed or copied from the web page, never seen by agents.
- **Agents that need root** should get narrow sudo rules on each machine (named commands, no password), not an admin password. Handing an agent the password through `agentvault-cli run` works, but gives it full admin rights; the vault would only add a log line and a revoke button.
- **The vault as an SSH agent:** it keeps SSH private keys and signs logins on request over the tailnet, like 1Password's SSH agent. The key never leaves the vault, every login is logged and limited by token, and revoking a token cuts access at once. Tailscale SSH (access decided by tailnet rules, no keys) is the alternative for machines on the tailnet.

