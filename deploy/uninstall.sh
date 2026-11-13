#!/bin/sh
# Removes the keys service.
#
#   sudo deploy/uninstall.sh           remove the program and service; KEEP your
#                                      vault (/var/lib/keys) and config (/etc/keys)
#   sudo deploy/uninstall.sh --purge   also securely delete the vault, config and
#                                      the keys user. This cannot be undone.
set -eu
[ "$(id -u)" = 0 ] || { echo "Run it with sudo." >&2; exit 1; }

systemctl disable --now keys keys-cert.timer 2>/dev/null || true
rm -f /etc/systemd/system/keys.service /etc/systemd/system/keys-cert.service /etc/systemd/system/keys-cert.timer
systemctl daemon-reload
rm -f /usr/local/bin/keys
rm -rf /usr/local/lib/keys /opt/keys

if [ "${1:-}" != --purge ]; then
  echo "Removed the keys service and program."
  echo "Your vault is still in /var/lib/keys and your settings in /etc/keys: reinstalling picks them up."
  echo "To delete them too: sudo $0 --purge"
  exit 0
fi

if [ -t 0 ]; then
  printf 'This permanently deletes every secret in the vault. Type "delete" to confirm: '
  read -r ANSWER
  [ "$ANSWER" = delete ] || { echo "Nothing deleted."; exit 1; }
fi
find /var/lib/keys /etc/keys -type f -exec shred -u {} + 2>/dev/null || true
rm -rf /var/lib/keys /etc/keys
id keys >/dev/null 2>&1 && userdel keys 2>/dev/null || true
echo "Removed the keys service, the vault, its settings and the keys user."
