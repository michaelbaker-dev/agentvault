---
name: agentvault
description: Use the owner's AgentVault for any API key, token, password or other credential. Use it whenever a task needs to call a third-party API (OpenAI, Anthropic, GitHub, Cloudflare, Slack, Hugging Face, OpenRouter, Tavily, market-data APIs and the like), when code, a script or a test needs a key, when the user mentions keys, secrets, credentials, tokens, .env files or "the vault", and always before asking the user for a key.
---

# AgentVault

The owner keeps their API keys in a vault on their Tailscale network. You can use a key without ever seeing it: the vault attaches the key to requests on its side.

## Choose the access path

1. **MCP tools.** If the vault's MCP tools (`list_secrets`, `describe_secret`, `proxy_request`) are available, use them. The server is called `agentvault`, or `keys` on older setups.
2. **Otherwise use the helper.** Run `scripts/agentvault-cli` from this skill's folder (usually `~/.claude/skills/agentvault/scripts/agentvault-cli`). Start with `agentvault-cli check`.
3. **If neither is set up**, show the owner the steps under "Setup" below. Don't fall back to asking for the key itself.

## Rules

- Never ask the user to paste a key, token or password into the chat.
- Never put a key in source code, `.env` files, commits, logs or command-line arguments.
- Never read or print the vault token, whether from `~/.config/agentvault/token` or from an MCP header.
- Use the key through the proxy (`proxy_request` or `agentvault-cli call`). Don't fetch its raw value to look at it.
- Send read-only requests (GET) unless the user asked for a change. Before anything that spends money, sends messages, deletes things or changes production, check the key's `risk` with describe and confirm with the user.
- Some keys are owner-only by design: passwords, wallet keys, and the "manager" keys used for rotation. They're invisible to you, and a 404 for them is expected. The owner uses those through the web interface.
- If a key is marked exposed or rejected, mention it to the user. Replacing it is done with **Rotate** in the web interface.
- A **UniFi console API key (local)** works only on its own console's network: the vault can't check or proxy it from elsewhere. Use it with `agentvault-cli run` from a machine on that network (needs the read scope), and pass it to tools through their input, not on the command line.

## Helper commands

| Command | What it does |
|---|---|
| `agentvault-cli check` | Shows whether the vault is reachable and unlocked, and how many keys this token can use. |
| `agentvault-cli list [word]` | Lists usable keys with provider, risk and whether the proxy can reach them. No values. |
| `agentvault-cli describe NAME` | Shows what a key is for, its account, its risk, and `proxy_target` (the address `call` paths are relative to). |
| `agentvault-cli call NAME PATH [-X METHOD] [-q QUERY] [-H 'K: V'] [-d JSON or @file] [-o FILE]` | Calls the provider through the vault, showing how long the vault and the provider each took. Example: `agentvault-cli call OPENAI_API_KEY /v1/models`. Replies over 100 KB are cut when shown; `-o FILE` saves the whole reply (`-o -` writes it to stdout for a pipe), then read it with `jq`, `grep` or `head`. |
| `agentvault-cli run NAME[=ENVVAR] ... -- COMMAND` | Runs a program with the key in its environment, with the value blanked out of its output. Needs a token with the read scope. Use it for running the user's own code or tests. |
| `agentvault-cli github-push OWNER/REPO [--branch B] [-C DIR] [--dry-run]` | Pushes a local branch to GitHub through the vault. See "Pushing to GitHub" below. |

Download links are handled for you: GitHub's CI logs (`/repos/OWNER/REPO/actions/jobs/ID/logs`), for example, redirect to a signed link that `proxy_request` and `agentvault-cli call` fetch without any key. Don't change CI workflows just to see their output.

The proxy path is relative to the provider's API base. For example, GitHub's base is `https://api.github.com`, so `/user` calls `https://api.github.com/user`. Don't add any authentication header yourself.

## Pushing to GitHub

When the owner asks you to push commits to GitHub and this machine has no git credentials, use the helper:

```sh
agentvault-cli github-push OWNER/REPO --dry-run   # shows what would be sent
agentvault-cli github-push OWNER/REPO             # sends it
```

- It sends the commits through GitHub's API via the vault's proxy, so it needs no SSH key, no deploy key and no read scope, and the GitHub key never leaves the vault. Don't ask for any of those, and don't use `git push` with a key fetched through `run`.
- Each commit is recreated exactly (GitHub must compute the same commit ID) before the branch moves. It works on empty repositories and new branches.
- It only fast-forwards. If GitHub has commits this clone lacks, or the histories diverged, it refuses and pushes nothing. Tell the owner; never force anything.
- It needs a token whose proxy allows more than GET. If the vault refuses with "GET requests only", tell the owner: they untick that box on the token for the push and can tick it again afterwards.
- Only push, create repositories or change repository settings when the owner asked for that specific repository. If Claude Code's permission check blocks a GitHub write, stop and tell the owner; don't look for another route around it.
- For other GitHub changes (a release, a tag, a repository setting), use `agentvault-cli call` or `proxy_request` against GitHub's API, with the same care. A lightweight tag, for example: `agentvault-cli call KEY /repos/OWNER/REPO/git/refs -X POST -d '{"ref":"refs/tags/v0.1.0","sha":"<commit>"}'`.
- Files over 7 MB can't go through the proxy; the command says so and stops.

## Writing code that needs a key

Don't hard-code keys or read them from `.env`. In order of preference:

1. **Call through the vault's proxy.** The app sends `Authorization: Bearer $AGENTVAULT_TOKEN` to `$KEYS_URL/v1/proxy/NAME/<provider path>` and never holds the provider key:
   ```python
   import json, os, urllib.request
   def via_vault(name, path, body=None):
       req = urllib.request.Request(f"{os.environ['KEYS_URL']}/v1/proxy/{name}/{path.lstrip('/')}",
           data=json.dumps(body).encode() if body is not None else None,
           headers={"Authorization": f"Bearer {os.environ['AGENTVAULT_TOKEN']}", "Content-Type": "application/json"})
       return json.load(urllib.request.urlopen(req))
   ```
2. **Fetch the value at startup** when an SDK insists on the raw key: `GET $KEYS_URL/v1/secrets/NAME/value` returns `{"value": ...}`. Keep the value in memory only.
3. **For local runs**, wrap the command instead of changing code: `agentvault-cli run OPENAI_API_KEY -- python app.py`.

Tell the user that each app should get its own token from the web interface (**Tokens**), limited to the keys it needs and to the machines it runs on.

## When something fails

| Vault says | Meaning | What to do |
|---|---|---|
| 503 locked | The vault restarted and isn't unlocked. | Ask the owner to sign in at the vault's web address. |
| 401 | The token is missing, wrong or revoked. | Ask the owner for a new token, set up as below. |
| 403 | This token can't do that: wrong scope, key outside its list, or another machine. | Say which key or scope is missing. |
| 404 | No such key, or it's owner-only. | Run `list` to see what's available. |
| 400 "no proxy target" | The vault doesn't know the key's API address. | The owner sets a base URL on the key in the web interface. |
| An error from the provider (e.g. GitHub "Bad credentials") | The key itself was refused. | Tell the user the key may be revoked or expired and needs rotating. |

## Setup (steps for the owner, not for you)

1. In the vault's web interface, under **Tokens**, make a token with the preset **Claude / agents** (list + proxy, GET-only), tied to this machine. Add the read scope only if `agentvault-cli run` is wanted.
2. In their own terminal, not through you, run `~/.claude/skills/agentvault/scripts/agentvault-cli setup`. It asks for the token without showing it, checks it, saves it for the helper, and connects Claude Code's MCP server for all projects.
3. Restart Claude Code.

**Several projects on one machine:** each can have its own token, so the vault's log shows which project did what and one can be revoked alone. The owner makes a token per project and runs `agentvault-cli setup --project` inside each project's folder. `agentvault-cli check` says which token is in use.
