#!/bin/sh
# Installs keys as a hardened system service, or upgrades an existing install
# (your config, data and automatic-unlock setting are kept).
#
#   From source:            cargo build --release && sudo deploy/install.sh
#   From a release archive: sudo ./install.sh        (the keys binary sits next to it)
#
# Tagged machine? Tell it whose vault it is: sudo KEYS_OWNER=you@example.com deploy/install.sh
set -eu
fail() { printf '\n%s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail "Run it with sudo."
cd "$(dirname "$0")"
[ -d deploy ] || [ ! -d ../deploy ] || cd ..

# ---- the program
if [ -n "${KEYS_BIN:-}" ]; then BIN=$KEYS_BIN
elif [ -x target/release/keys ]; then BIN=target/release/keys
elif [ -x ./keys ] && [ ! -d ./keys ]; then BIN=./keys
else fail "No keys program found. Build it first (cargo build --release), or run this from an unpacked release."
fi
DEPLOY=deploy; [ -d deploy ] || DEPLOY=.

# ---- prerequisites, checked before anything is changed
[ -d /run/systemd/system ] || fail "This needs a Linux system running systemd."
for c in tailscale python3 curl systemd-creds useradd; do
  command -v "$c" >/dev/null 2>&1 || fail "Missing '$c'. Install it and run this again."
done
STATUS=$(tailscale status --json 2>/dev/null) || fail "Tailscale isn't running here. Start it and sign in: sudo tailscale up"
py() { printf '%s' "$STATUS" | python3 -c "import json,sys; d=json.load(sys.stdin); $1"; }
[ "$(py 'print(d.get("BackendState"))')" = Running ] || fail "Tailscale isn't connected. Sign in first: sudo tailscale up"
HOST=$(py 'print((d["Self"].get("DNSName") or "").rstrip("."))')
[ -n "$HOST" ] || fail "MagicDNS is off for your tailnet. Turn it on: https://login.tailscale.com/admin/dns"
[ -n "$(py 'print(" ".join(d.get("CertDomains") or []))')" ] || fail "HTTPS certificates are off for your tailnet. Turn them on under
'HTTPS Certificates' at https://login.tailscale.com/admin/dns (see https://tailscale.com/kb/1153/enabling-https)."
IP=$(py 'print([a for a in d["Self"]["TailscaleIPs"] if "." in a][0])')
if [ -n "${KEYS_OWNER:-}" ]; then OWNER=$KEYS_OWNER
else
  OWNER=$(py 'print(d["User"][str(d["Self"]["UserID"])]["LoginName"])')
  case $OWNER in *@*) ;; *)
    fail "This machine is tagged, so Tailscale can't say whose vault it is. Run it again with your Tailscale login:
  sudo KEYS_OWNER=you@example.com $0" ;;
  esac
fi
if [ ! -f /etc/keys/config.toml ] && ! systemctl is-active --quiet keys 2>/dev/null; then
  if ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "^(\*|0\.0\.0\.0|\[::\]|$IP):443$"; then
    fail "Something already listens on port 443 here. Stop it, or install, then change 'listen' in /etc/keys/config.toml to another port."
  fi
fi

id keys >/dev/null 2>&1 || useradd --system --home-dir /var/lib/keys --shell /usr/sbin/nologin keys
install -m 0755 "$BIN" /usr/local/bin/keys
install -d -m 0755 /usr/local/lib/keys /opt/keys
install -m 0755 "$DEPLOY"/refresh-cert /usr/local/lib/keys/refresh-cert
install -m 0755 "$DEPLOY"/auto-unlock /usr/local/lib/keys/auto-unlock
[ -f README.md ] && install -m 0644 README.md /opt/keys/README.md
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
install -m 0644 "$DEPLOY"/keys.service "$DEPLOY"/keys-cert.service "$DEPLOY"/keys-cert.timer /etc/systemd/system/
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
