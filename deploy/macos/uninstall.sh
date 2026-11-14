#!/bin/sh
# Removes agentvault's background service from this Mac.
#
#   deploy/macos/uninstall.sh            stop it and remove the program; your vault
#                                        (encrypted data, config, certificate) stays
#   deploy/macos/uninstall.sh --purge    also delete the vault itself and the
#                                        passphrase stored for automatic unlock
set -eu
[ "$(uname -s)" = Darwin ] || { echo "This is the Mac uninstaller. On Linux, use deploy/uninstall.sh." >&2; exit 1; }
[ "$(id -u)" != 0 ] || { echo "Run it as yourself, without sudo." >&2; exit 1; }
APP="$HOME/Library/Application Support/AgentVault"
LOGS="$HOME/Library/Logs/AgentVault"
LABEL=com.agentvault
GUI="gui/$(id -u)"

if [ "${1:-}" = --purge ]; then
  printf 'This deletes your vault and every key in it, for good. Type "delete my vault" to go on: '
  read -r ANSWER
  [ "$ANSWER" = "delete my vault" ] || { echo "Nothing was changed."; exit 1; }
  # Only the program that stored the Keychain passphrase can remove it, and
  # only inside your login session.
  if [ -x "$APP/bin/agentvault" ] && [ -f "$APP/config.toml" ]; then
    out=$(mktemp -t agentvault); job="$LABEL.oneshot.$$"; spec="$out.plist"
    python3 - "$job" "$out" "$APP/bin/agentvault" auto-unlock -c "$APP/config.toml" --off > "$spec" <<'PY'
import plistlib, sys
job, out, *args = sys.argv[1:]
sys.stdout.buffer.write(plistlib.dumps({"Label": job, "ProgramArguments": args, "StandardOutPath": out,
                                        "StandardErrorPath": out, "RunAtLoad": True}))
PY
    launchctl bootstrap "$GUI" "$spec" 2>/dev/null && sleep 3
    launchctl bootout "$GUI/$job" 2>/dev/null || true
    rm -f "$out" "$spec"
  fi
fi

launchctl bootout "$GUI/$LABEL" 2>/dev/null || true
rm -f "$HOME/Library/LaunchAgents/$LABEL.plist" "$APP/bin/agentvault"
rmdir "$APP/bin" 2>/dev/null || true

if [ "${1:-}" = --purge ]; then
  rm -rf "$APP" "$LOGS"
  echo "Removed agentvault and deleted your vault."
else
  echo "Removed the agentvault service. Your vault is still in $APP;"
  echo "install again to pick it up, or run this with --purge to delete it."
fi
