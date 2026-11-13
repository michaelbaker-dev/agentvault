#!/bin/sh
# Installs keys as a hardened system service. Run from the repository root:
#   cargo build --release && sudo deploy/install.sh
set -eu
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
cd "$(dirname "$0")/.."
BIN=target/release/keys
[ -x "$BIN" ] || { echo "build first: cargo build --release" >&2; exit 1; }

STATUS=$(tailscale status --json)
HOST=$(printf '%s' "$STATUS" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["DNSName"].rstrip("."))')
IP=$(printf '%s' "$STATUS" | python3 -c 'import json,sys; print([a for a in json.load(sys.stdin)["Self"]["TailscaleIPs"] if "." in a][0])')
OWNER=$(printf '%s' "$STATUS" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["User"][str(d["Self"]["UserID"])]["LoginName"])')

id keys >/dev/null 2>&1 || useradd --system --home-dir /var/lib/keys --shell /usr/sbin/nologin keys
install -m 0755 "$BIN" /usr/local/bin/keys
install -d -m 0755 /usr/local/lib/keys /opt/keys
install -m 0755 deploy/refresh-cert /usr/local/lib/keys/refresh-cert
install -m 0755 deploy/auto-unlock /usr/local/lib/keys/auto-unlock
install -m 0644 README.md /opt/keys/README.md
install -d -m 0750 -g keys /etc/keys
if [ ! -f /etc/keys/config.toml ]; then
  cat > /etc/keys/config.toml <<CONF
# keys configuration. See config.example.toml for every option.
listen = "$IP:443"
hostname = "$HOST"
owner = "$OWNER"
data_dir = "/var/lib/keys/data"

[tls]
cert_file = "/var/lib/keys/tls/cert.pem"
key_file = "/var/lib/keys/tls/key.pem"
CONF
  chgrp keys /etc/keys/config.toml && chmod 0640 /etc/keys/config.toml
fi
install -m 0644 deploy/keys.service deploy/keys-cert.service deploy/keys-cert.timer /etc/systemd/system/
# Reinstalling or upgrading keeps automatic unlock on if it was.
if [ -f /etc/keys/passphrase.cred ]; then
  sed -i 's/^#LoadCredentialEncrypted=/LoadCredentialEncrypted=/' /etc/systemd/system/keys.service
fi
systemctl daemon-reload
systemctl enable --now keys-cert.timer
systemctl enable keys
systemctl restart keys
sleep 2
systemctl --no-pager --lines=5 status keys || true
echo
if [ -f /etc/keys/passphrase.cred ]; then
  echo "Done. The vault unlocks itself at https://$HOST"
  exit 0
fi
echo "Open https://$HOST in a browser on one of $OWNER's devices to set your passphrase (or sign in, if you already have)."
if [ -t 0 ]; then
  echo
  printf 'Unlock the vault automatically after a reboot? [Y/n] '
  read -r ANSWER
  case $ANSWER in [nN]*)
    echo "OK: sign in after each restart to unlock it. To change your mind: sudo /usr/local/lib/keys/auto-unlock"
    exit 0 ;;
  esac
  printf 'Set your passphrase in the browser first, then press Enter here. '
  read -r _
  exec /usr/local/lib/keys/auto-unlock
fi
echo "To unlock automatically after a reboot, then run: sudo /usr/local/lib/keys/auto-unlock"
