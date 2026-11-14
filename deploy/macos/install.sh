#!/bin/sh
# Installs agentvault on a Mac as a background service for your account, or
# upgrades an existing install (config, data and automatic unlock are kept).
# No sudo: the vault runs as you, in your login session, so it can use your
# login Keychain for automatic unlock.
#
#   From source:            cargo build --release && deploy/macos/install.sh
#   From a release archive: ./install.sh        (the agentvault binary sits next to it)
#
# Unattended: AGENTVAULT_AUTO_UNLOCK=yes (or no) answers the automatic-unlock question.
set -eu
fail() { printf '\n%s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = Darwin ] || fail "This is the Mac installer. On Linux, use deploy/install.sh."
[ "$(id -u)" != 0 ] || fail "Run it as yourself, without sudo: the vault runs as your account."
cd "$(dirname "$0")"
[ -d ../../deploy/macos ] && cd ../..

# ---- the program
if [ -n "${AGENTVAULT_BIN:-}" ]; then BIN=$AGENTVAULT_BIN
elif [ -x target/release/agentvault ]; then BIN=target/release/agentvault
elif [ -x ./agentvault ] && [ ! -d ./agentvault ]; then BIN=./agentvault
else fail "No agentvault program found. Build it first (cargo build --release), or run this from an unpacked release."
fi

# ---- prerequisites, checked before anything is changed
for c in python3 curl launchctl; do
  command -v "$c" >/dev/null 2>&1 || fail "Missing '$c'. Install Xcode's command-line tools (xcode-select --install) and run this again."
done
TSDIR=
for d in /Applications/Tailscale.app/Contents/MacOS /usr/local/bin /opt/homebrew/bin; do
  [ -x "$d/tailscale" ] && { TSDIR=$d; break; }
done
[ -n "$TSDIR" ] || fail "Tailscale isn't installed. Get it from https://tailscale.com/download/mac and sign in."
TS="$TSDIR/tailscale"
STATUS=$("$TS" status --json 2>/dev/null) || fail "Tailscale isn't running. Open the Tailscale app and sign in."
py() { printf '%s' "$STATUS" | python3 -c "import json,sys; d=json.load(sys.stdin); $1"; }
[ "$(py 'print(d.get("BackendState"))')" = Running ] || fail "Tailscale isn't connected. Open the Tailscale app and sign in."
HOST=$(py 'print((d["Self"].get("DNSName") or "").rstrip("."))')
[ -n "$HOST" ] || fail "MagicDNS is off for your tailnet. Turn it on: https://login.tailscale.com/admin/dns"
[ -n "$(py 'print(" ".join(d.get("CertDomains") or []))')" ] || fail "HTTPS certificates are off for your tailnet. Turn them on under
'HTTPS Certificates' at https://login.tailscale.com/admin/dns (see https://tailscale.com/kb/1153/enabling-https)."
IP=$(py 'print([a for a in d["Self"]["TailscaleIPs"] if "." in a][0])')
if [ -n "${AGENTVAULT_OWNER:-}" ]; then OWNER=$AGENTVAULT_OWNER
else
  OWNER=$(py 'print(d["User"][str(d["Self"]["UserID"])]["LoginName"])')
  case $OWNER in *@*) ;; *)
    fail "This Mac is tagged, so Tailscale can't say whose vault it is. Run it again with your Tailscale login:
  AGENTVAULT_OWNER=you@example.com $0" ;;
  esac
fi
GUI="gui/$(id -u)"
launchctl print "$GUI" >/dev/null 2>&1 || fail "You need to be logged in on the Mac (at its screen, or with screen sharing) for the vault to run in your session."

APP="$HOME/Library/Application Support/AgentVault"
LOGS="$HOME/Library/Logs/AgentVault"
LABEL=com.agentvault
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
CONF="$APP/config.toml"

# Runs a command inside your login session (where the Keychain is open) and
# prints its output; works from Terminal and over SSH alike.
in_session() {
  out=$(mktemp -t agentvault); job="$LABEL.oneshot.$$"; spec="$out.plist"
  python3 - "$job" "$out" "$@" > "$spec" <<'PY'
import plistlib, sys
job, out, *args = sys.argv[1:]
sys.stdout.buffer.write(plistlib.dumps({"Label": job, "ProgramArguments": args, "StandardOutPath": out,
                                        "StandardErrorPath": out, "RunAtLoad": True}))
PY
  launchctl bootstrap "$GUI" "$spec"
  i=0
  while [ $i -lt 60 ] && launchctl print "$GUI/$job" 2>/dev/null | grep -q "state = running"; do sleep 1; i=$((i + 1)); done
  sleep 1
  launchctl bootout "$GUI/$job" 2>/dev/null || true
  cat "$out"; rm -f "$out" "$spec"
}

mkdir -p "$APP/bin" "$APP/data" "$APP/tls" "$LOGS" "$HOME/Library/LaunchAgents"
chmod 700 "$APP" "$APP/data" "$APP/tls"

# ---- upgrading: only the program that stored the Keychain passphrase can
# remove it, so the old one does that now; you sign in once afterwards and
# the new one stores it again.
REARM=no
if [ -x "$APP/bin/agentvault" ] && [ -f "$CONF" ] && ! cmp -s "$APP/bin/agentvault" "$BIN"; then
  case $(in_session "$APP/bin/agentvault" auto-unlock -c "$CONF" --off) in *Removed*) REARM=yes ;; esac
fi

# ---- config (kept on upgrade)
if [ ! -f "$CONF" ]; then
  PORT=
  for p in 9443 9444 9445 9446 9447 9448 9449; do
    if python3 -c "import socket,sys; s=socket.socket(); s.bind((sys.argv[1], int(sys.argv[2])))" "$IP" "$p" 2>/dev/null; then PORT=$p; break; fi
  done
  [ -n "$PORT" ] || fail "Ports 9443-9449 are all in use on $IP. Free one, or write $CONF yourself (see config.example.toml)."
  cat > "$CONF" <<CONF
# agentvault configuration. See config.example.toml for every option.
# macOS: a normal account can't use port 443, so the vault has its own port.
listen = "$IP:$PORT"
hostname = "$HOST"
owner = "$OWNER"
data_dir = "$APP/data"

[tls]
cert_file = "$APP/tls/cert.pem"
key_file = "$APP/tls/key.pem"
# The vault runs as you, and Tailscale lets you fetch certificates.
renew_with_tailscale = true
CONF
  chmod 600 "$CONF"
fi
LISTEN=$(sed -n 's/^listen *= *"\(.*\)"/\1/p' "$CONF")
PORT=${LISTEN##*:}
URL="https://$HOST"; [ "$PORT" = 443 ] || URL="$URL:$PORT"
[ -s "$APP/tls/cert.pem" ] || "$TS" cert --cert-file "$APP/tls/cert.pem" --key-file "$APP/tls/key.pem" "$HOST" >/dev/null ||
  fail "Couldn't get an HTTPS certificate from Tailscale (tailscale cert $HOST)."
chmod 600 "$APP/tls/key.pem"

# ---- the program and the service
cp "$BIN" "$APP/bin/agentvault.new" && chmod 755 "$APP/bin/agentvault.new" && mv "$APP/bin/agentvault.new" "$APP/bin/agentvault"
python3 - "$PLIST" "$LABEL" "$APP/bin/agentvault" "$CONF" "$LOGS/agentvault.log" "$TSDIR" <<'PY'
import plistlib, sys
plist, label, binary, conf, log, tsdir = sys.argv[1:]
spec = {
    "Label": label,
    "ProgramArguments": [binary, "serve", "-c", conf],
    "RunAtLoad": True,
    "KeepAlive": True,
    "ThrottleInterval": 10,
    "ProcessType": "Background",
    "StandardOutPath": log,
    "StandardErrorPath": log,
    "EnvironmentVariables": {"PATH": f"/usr/bin:/bin:/usr/sbin:/sbin:{tsdir}"},
}
with open(plist, "wb") as f:
    plistlib.dump(spec, f)
PY
launchctl bootout "$GUI/$LABEL" 2>/dev/null || true
launchctl bootstrap "$GUI" "$PLIST"
launchctl enable "$GUI/$LABEL"

# ---- wait for it to answer
STATE=down; i=0
while [ $i -lt 30 ]; do
  STATE=$(curl -s --max-time 5 "$URL/v1/status" 2>/dev/null | python3 -c 'import json,sys
try: d = json.load(sys.stdin)
except Exception: print("down"); raise SystemExit
print("new" if not d.get("initialized") else "sealed" if d.get("sealed") else "unlocked")') || STATE=down
  [ "$STATE" != down ] && break
  sleep 1; i=$((i + 1))
done
[ "$STATE" != down ] || fail "The vault didn't start. See $LOGS/agentvault.log"

# ---- automatic unlock
want=${AGENTVAULT_AUTO_UNLOCK:-}
if [ "$REARM" = yes ]; then want=yes
elif [ -z "$want" ] && [ "$STATE" = unlocked ]; then want=keep
elif [ -z "$want" ] && [ -t 0 ]; then
  printf 'Unlock the vault automatically after restarts (your passphrase is kept in your login Keychain)? [Y/n] '
  read -r ANSWER
  case $ANSWER in [nN]*) want=no ;; *) want=yes ;; esac
fi
[ "$want" = yes ] && "$APP/bin/agentvault" auto-unlock -c "$CONF" --at-next-sign-in >/dev/null

echo
echo "AgentVault is running at $URL"
case $STATE in
  new) echo "Open it in a browser on one of $OWNER's devices to set your passphrase." ;;
  sealed) echo "Sign in there to unlock it." ;;
  unlocked) echo "It unlocked itself." ;;
esac
[ "$want" = yes ] && echo "It will unlock itself after restarts once you've signed in there."
[ "$want" = no ] && echo "To unlock it automatically later: $APP/bin/agentvault auto-unlock -c \"$CONF\" --at-next-sign-in, then sign in."
echo "Logs: $LOGS/agentvault.log   Uninstall: deploy/macos/uninstall.sh"
