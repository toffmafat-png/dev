#!/usr/bin/env bash
# Clean user-level uninstaller for NOVA X. Preserves ~/.local/share/nova-x unless --purge-data is passed.
set -euo pipefail

PURGE_DATA=0
if [ "${1:-}" = "--purge-data" ]; then
  PURGE_DATA=1
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl --user disable --now nova-x-worker.service >/dev/null 2>&1 || true
fi

rm -f "${HOME}/.local/bin/nova-x" \
      "${HOME}/.local/share/applications/nova-x.desktop" \
      "${HOME}/.local/share/icons/hicolor/scalable/apps/nova-x.svg" \
      "${HOME}/.config/systemd/user/nova-x-worker.service"

if [ "$PURGE_DATA" -eq 1 ]; then
  rm -rf "${HOME}/.local/share/nova-x" "${HOME}/.config/nova-x"
  echo "Removed NOVA X user launchers AND purged ~/.local/share/nova-x user data."
else
  echo "Removed NOVA X user launchers. Preserved ~/.local/share/nova-x (pass --purge-data to delete user data)."
fi
