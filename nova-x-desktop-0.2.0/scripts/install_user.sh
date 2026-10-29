#!/usr/bin/env bash
# Non-root user-level installer for NOVA X on Kali Linux / Debian.
set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
  echo "error: Do not run install_user.sh as root. NOVA X installs into your user account." >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${NOVA_VENV_DIR:-$ROOT/.venv}"
BIN_DIR="${HOME}/.local/bin"
APP_DIR="${HOME}/.local/share/applications"
ICON_DIR="${HOME}/.local/share/icons/hicolor/scalable/apps"
SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"

python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -r "$ROOT/requirements.txt"

install -d "$BIN_DIR" "$APP_DIR" "$ICON_DIR" "$SYSTEMD_USER_DIR"

cat > "$BIN_DIR/nova-x" <<EOF
#!/usr/bin/env bash
exec "$VENV_DIR/bin/python" -m nova.desktop.cli "\$@"
EOF
chmod 0755 "$BIN_DIR/nova-x"

sed "s|^Exec=.*|Exec=$BIN_DIR/nova-x|" "$ROOT/packaging/debian/nova-x.desktop" > "$APP_DIR/nova-x.desktop"
chmod 0644 "$APP_DIR/nova-x.desktop"
install -m 0644 "$ROOT/packaging/debian/nova-x.svg" "$ICON_DIR/nova-x.svg"

sed "s|^ExecStart=.*|ExecStart=$BIN_DIR/nova-x worker --poll-seconds 30|" \
  "$ROOT/packaging/debian/nova-x-worker.service" > "$SYSTEMD_USER_DIR/nova-x-worker.service"
chmod 0644 "$SYSTEMD_USER_DIR/nova-x-worker.service"

echo "Installed NOVA X launcher to $BIN_DIR/nova-x (optional worker unit staged, NOT enabled by default)."
echo "Run '$BIN_DIR/nova-x setup' to verify environment or '$BIN_DIR/nova-x' to launch the native desktop app."
