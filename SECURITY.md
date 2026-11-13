# Security policy

keys holds other people's credentials, so security reports are the most useful contribution there is.

## Reporting a vulnerability

**Please don't open a public issue.** Report it privately through GitHub instead: on this repository, open **Security → Report a vulnerability**. Include what you found, how to reproduce it, and what an attacker could do with it.

You'll get an acknowledgement within a week. Fixed issues are credited in the release notes unless you'd rather not be named.

## Supported versions

Only the latest release gets security fixes while the project is at 0.x.

## Scope

In scope: anything that lets someone read, use or change a secret, token or the audit log beyond what the [security model](README.md#security-model) allows. Examples:
- a way around token scopes, machine pinning or the owner-only flag;
- a key reaching a caller through the proxy;
- a way to sign in without the passphrase;
- an injection;
- a weakness in the encryption.

Already known and documented under "Not covered" in the README:
- someone with root on the vault machine;
- misuse within a token's own scopes;
- rewriting the end of the audit log by someone who can write the database file.

## Status

The project has not had an independent security audit. The automatic rotators are tested against simulated providers only. See [Limitations](README.md#limitations).
