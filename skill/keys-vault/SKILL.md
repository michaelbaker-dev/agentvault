---
name: keys-vault
description: Use the owner's keys vault for any API key, token, password or other credential. Use it whenever a task needs to call a third-party API (OpenAI, Anthropic, GitHub, Cloudflare, Slack, Hugging Face, OpenRouter, Tavily, market-data APIs and the like), when code, a script or a test needs a key, when the user mentions keys, secrets, credentials, tokens, .env files or "the vault", and always before asking the user for a key.
---

# Keys vault

The owner keeps their API keys in a vault on their Tailscale network. You can use a key without ever seeing it: the vault attaches the key to requests on its side.

## Choose the access path

1. **MCP tools.** If the `keys` server's tools are available (`list_secrets`, `describe_secret`, `proxy_request`), use them.
2. **Otherwise use the helper.** Run `scripts/keys-cli` from this skill's folder (usually `~/.claude/skills/keys-vault/scripts/keys-cli`). Start with `keys-cli check`.
3. **If neither is set up**, show the owner the steps under "Setup" below. Don't fall back to asking for the key itself.

## Rules

- Never ask the user to paste a key, token or password into the chat.
- Never put a key in source code, `.env` files, commits, logs or command-line arguments.
- Never read or print the vault token, whether from `~/.config/keys/token` or from an MCP header.
- Use the key through the proxy (`proxy_request` or `keys-cli call`). Don't fetch its raw value to look at it.
- Send read-only requests (GET) unless the user asked for a change. Before anything that spends money, sends messages, deletes things or changes production, check the key's `risk` with describe and confirm with the user.
- Some keys are owner-only by design: passwords, wallet keys, and the "manager" keys used for rotation. They're invisible to you, and a 404 for them is expected. The owner uses those through the web interface.
- If a key is marked exposed or rejected, mention it to the user. Replacing it is done with **Rotate** in the web interface.

## Helper commands

| Command | What it does |
|---|---|
| `keys-cli check` | Shows whether the vault is reachable and unlocked, and how many keys this token can use. |
| `keys-cli list [word]` | Lists usable keys with provider, risk and whether the proxy can reach them. No values. |
| `keys-cli describe NAME` | Shows what a key is for, its account, its risk, and `proxy_target` (the address `call` paths are relative to). |
| `keys-cli call NAME PATH [-X METHOD] [-q QUERY] [-H 'K: V'] [-d JSON or @file]` | Calls the provider through the vault. Example: `keys-cli call OPENAI_API_KEY /v1/models` |
| `keys-cli run NAME[=ENVVAR] ... -- COMMAND` | Runs a program with the key in its environment, with the value blanked out of its output. Needs a token with the read scope. Use it for running the user's own code or tests. |

The proxy path is relative to the provider's API base. For example, GitHub's base is `https://api.github.com`, so `/user` calls `https://api.github.com/user`. Don't add any authentication header yourself.

## Writing code that needs a key

Don't hard-code keys or read them from `.env`. In order of preference:

1. **Call through the vault's proxy.** The app sends `Authorization: Bearer $KEYS_TOKEN` to `$KEYS_URL/v1/proxy/NAME/<provider path>` and never holds the provider key:
   ```python
   import json, os, urllib.request
   def via_vault(name, path, body=None):
       req = urllib.request.Request(f"{os.environ['KEYS_URL']}/v1/proxy/{name}/{path.lstrip('/')}",
           data=json.dumps(body).encode() if body is not None else None,
           headers={"Authorization": f"Bearer {os.environ['KEYS_TOKEN']}", "Content-Type": "application/json"})
       return json.load(urllib.request.urlopen(req))
   ```
2. **Fetch the value at startup** when an SDK insists on the raw key: `GET $KEYS_URL/v1/secrets/NAME/value` returns `{"value": ...}`. Keep the value in memory only.
3. **For local runs**, wrap the command instead of changing code: `keys-cli run OPENAI_API_KEY -- python app.py`.

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

1. In the vault's web interface, under **Tokens**, make a token with the preset **Claude / agents** (list + proxy, GET-only), tied to this machine. Add the read scope only if `keys-cli run` is wanted.
2. In their own terminal, not through you, run `~/.claude/skills/keys-vault/scripts/keys-cli setup`. It asks for the token without showing it, checks it, saves it for the helper, and connects Claude Code's MCP server for all projects.
3. Restart Claude Code.
