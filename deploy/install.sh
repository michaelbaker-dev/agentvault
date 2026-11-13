#!/bin/sh
# Installs agentvault as a hardened system service, or upgrades an existing install
# (your config, data and automatic-unlock setting are kept).
#
#   From source:            cargo build --release && sudo deploy/install.sh
#   From a release archive: sudo ./install.sh        (the agentvault binary sits next to it)
#
# Tagged machine? Tell it whose vault it is: sudo AGENTVAULT_OWNER=you@example.com deploy/install.sh
set -eu
fail() { printf '\n%s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail "Run it with sudo."
cd "$(dirname "$0")"
[ -d deploy ] || [ ! -d ../deploy ] || cd ..

# ---- the program
if [ -n "${AGENTVAULT_BIN:-}" ]; then BIN=$AGENTVAULT_BIN
elif [ -x target/release/agentvault ]; then BIN=target/release/agentvault
elif [ -x ./agentvault ] && [ ! -d ./agentvault ]; then BIN=./agentvault
else fail "No agentvault program found. Build it first (cargo build --release), or run this from an unpacked release."
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
if [ -n "${AGENTVAULT_OWNER:-${KEYS_OWNER:-}}" ]; then OWNER=${AGENTVAULT_OWNER:-$KEYS_OWNER}
else
  OWNER=$(py 'print(d["User"][str(d["Self"]["UserID"])]["LoginName"])')
  case $OWNER in *@*) ;; *)
    fail "This machine is tagged, so Tailscale can't say whose vault it is. Run it again with your Tailscale login:
  sudo AGENTVAULT_OWNER=you@example.com $0" ;;
  esac
fi
# ---- move an install from before the rename (keys -> agentvault)
# Same vault, passphrase, tokens and automatic unlock; only names and paths change.
if [ -f /etc/keys/config.toml ] && [ ! -e /etc/agentvault ]; then
  echo "Moving your existing vault from the old 'keys' install to agentvault..."
  systemctl disable --now keys keys-cert.timer 2>/dev/null || true
  rm -f /etc/systemd/system/keys.service /etc/systemd/system/keys-cert.service /etc/systemd/system/keys-cert.timer
  systemctl daemon-reload
  id agentvault >/dev/null 2>&1 || useradd --system --home-dir /var/lib/agentvault --shell /usr/sbin/nologin agentvault
  mv /etc/keys /etc/agentvault
  if [ -d /var/lib/keys ]; then
    mv /var/lib/keys /var/lib/agentvault
    for ext in "" -wal -shm; do
      if [ -f "/var/lib/agentvault/data/keys.db$ext" ]; then
        mv "/var/lib/agentvault/data/keys.db$ext" "/var/lib/agentvault/data/agentvault.db$ext"
      fi
    done
    chown -R agentvault:agentvault /var/lib/agentvault
  fi
  sed -i 's#/var/lib/keys/#/var/lib/agentvault/#g; s/^# keys configuration/# agentvault configuration/' /etc/agentvault/config.toml
  chgrp agentvault /etc/agentvault /etc/agentvault/config.toml
  rm -f /usr/local/bin/keys
  rm -rf /usr/local/lib/keys /opt/keys
  userdel keys 2>/dev/null || true
  echo "Moved. Your vault is now in /var/lib/agentvault and its settings in /etc/agentvault."
fi

if [ ! -f /etc/agentvault/config.toml ] && ! systemctl is-active --quiet agentvault 2>/dev/null; then
  if ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "^(\*|0\.0\.0\.0|\[::\]|$IP):443$"; then
    fail "Something already listens on port 443 here. Stop it, or install, then change 'listen' in /etc/agentvault/config.toml to another port."
  fi
fi

id agentvault >/dev/null 2>&1 || useradd --system --home-dir /var/lib/agentvault --shell /usr/sbin/nologin agentvault
install -m 0755 "$BIN" /usr/local/bin/agentvault
install -d -m 0755 /usr/local/lib/agentvault /opt/agentvault
install -m 0755 "$DEPLOY"/refresh-cert /usr/local/lib/agentvault/refresh-cert
install -m 0755 "$DEPLOY"/auto-unlock /usr/local/lib/agentvault/auto-unlock
[ -f README.md ] && install -m 0644 README.md /opt/agentvault/README.md
install -d -m 0750 -g agentvault /etc/agentvault
if [ ! -f /etc/agentvault/config.toml ]; then
  cat > /etc/agentvault/config.toml <<CONF
# agentvault configuration. See config.example.toml for every option.
listen = "$IP:443"
hostname = "$HOST"
owner = "$OWNER"
data_dir = "/var/lib/agentvault/data"

[tls]
cert_file = "/var/lib/agentvault/tls/cert.pem"
key_file = "/var/lib/agentvault/tls/key.pem"
CONF
  chgrp agentvault /etc/agentvault/config.toml && chmod 0640 /etc/agentvault/config.toml
fi
install -m 0644 "$DEPLOY"/agentvault.service "$DEPLOY"/agentvault-cert.service "$DEPLOY"/agentvault-cert.timer /etc/systemd/system/
# Reinstalling or upgrading keeps automatic unlock on if it was.
if [ -f /etc/agentvault/passphrase.cred ]; then
  sed -i 's/^#LoadCredentialEncrypted=/LoadCredentialEncrypted=/' /etc/systemd/system/agentvault.service
fi
systemctl daemon-reload
systemctl enable --now agentvault-cert.timer
systemctl enable agentvault
systemctl restart agentvault
sleep 2
systemctl --no-pager --lines=5 status agentvault || true
echo
if [ -f /etc/agentvault/passphrase.cred ]; then
  echo "Done. The vault unlocks itself at https://$HOST"
  exit 0
fi
echo "Open https://$HOST in a browser on one of $OWNER's devices to set your passphrase (or sign in, if you already have)."
if [ -t 0 ]; then
  echo
  printf 'Unlock the vault automatically after a reboot? [Y/n] '
  read -r ANSWER
  case $ANSWER in [nN]*)
    echo "OK: sign in after each restart to unlock it. To change your mind: sudo /usr/local/lib/agentvault/auto-unlock"
    exit 0 ;;
  esac
  printf 'Set your passphrase in the browser first, then press Enter here. '
  read -r _
  exec /usr/local/lib/agentvault/auto-unlock
fi
echo "To unlock automatically after a reboot, then run: sudo /usr/local/lib/agentvault/auto-unlock"
