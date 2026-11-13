#!/bin/sh
# Removes the agentvault service.
#
#   sudo deploy/uninstall.sh           remove the program and service; KEEP your
#                                      vault (/var/lib/agentvault) and config (/etc/agentvault)
#   sudo deploy/uninstall.sh --purge   also securely delete the vault, config and
#                                      the agentvault user. This cannot be undone.
set -eu
[ "$(id -u)" = 0 ] || { echo "Run it with sudo." >&2; exit 1; }

systemctl disable --now agentvault agentvault-cert.timer 2>/dev/null || true
rm -f /etc/systemd/system/agentvault.service /etc/systemd/system/agentvault-cert.service /etc/systemd/system/agentvault-cert.timer
systemctl daemon-reload
rm -f /usr/local/bin/agentvault
rm -rf /usr/local/lib/agentvault /opt/agentvault

if [ "${1:-}" != --purge ]; then
  echo "Removed the agentvault service and program."
  echo "Your vault is still in /var/lib/agentvault and your settings in /etc/agentvault: reinstalling picks them up."
  echo "To delete them too: sudo $0 --purge"
  exit 0
fi

if [ -t 0 ]; then
  printf 'This permanently deletes every secret in the vault. Type "delete" to confirm: '
  read -r ANSWER
  [ "$ANSWER" = delete ] || { echo "Nothing deleted."; exit 1; }
fi
find /var/lib/agentvault /etc/agentvault -type f -exec shred -u {} + 2>/dev/null || true
rm -rf /var/lib/agentvault /etc/agentvault
id agentvault >/dev/null 2>&1 && userdel agentvault 2>/dev/null || true
echo "Removed the agentvault service, the vault, its settings and the agentvault user."
