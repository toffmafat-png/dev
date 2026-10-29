#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(python3 -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["project"]["version"])' "$ROOT/pyproject.toml")"
ARCH="all"
OUT_DIR="$ROOT/releases"
BUILD_DIR="$(mktemp -d "$ROOT/.nova-deb-build.XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT

PKG="$BUILD_DIR/package"
install -d "$PKG/DEBIAN" "$PKG/usr/lib/nova-x" "$PKG/usr/bin" \
  "$PKG/usr/share/applications" "$PKG/usr/share/icons/hicolor/scalable/apps" \
  "$PKG/usr/share/doc/nova-x-desktop"

install -m 0644 "$ROOT/packaging/debian/control" "$PKG/DEBIAN/control"
# Install pure-Python application source without bytecode, caches, tests, or local state.
python3 - "$ROOT/nova" "$PKG/usr/lib/nova-x/nova" <<'PY'
import shutil
import sys
from pathlib import Path
source, destination = map(Path, sys.argv[1:])
shutil.copytree(
    source,
    destination,
    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
)
PY

cat > "$PKG/usr/bin/nova-x" <<'EOF'
#!/usr/bin/python3
import sys
sys.path.insert(0, "/usr/lib/nova-x")
from nova.desktop.cli import main
raise SystemExit(main())
EOF
chmod 0755 "$PKG/usr/bin/nova-x"
install -m 0644 "$ROOT/packaging/debian/nova-x.desktop" "$PKG/usr/share/applications/nova-x.desktop"
install -m 0644 "$ROOT/packaging/debian/nova-x.svg" "$PKG/usr/share/icons/hicolor/scalable/apps/nova-x.svg"
install -m 0644 "$ROOT/packaging/debian/README.Debian" "$PKG/usr/share/doc/nova-x-desktop/README.Debian"
install -m 0644 "$ROOT/docs/NATIVE_DESKTOP.md" "$PKG/usr/share/doc/nova-x-desktop/README.native"
install -m 0644 "$ROOT/README.md" "$PKG/usr/share/doc/nova-x-desktop/README.upstream"

install -d "$OUT_DIR"
OUT="$OUT_DIR/nova-x-desktop_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$PKG" "$OUT"
echo "Built: $OUT"
dpkg-deb --info "$OUT"
