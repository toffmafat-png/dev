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
  "$PKG/usr/lib/systemd/user" \
  "$PKG/usr/share/polkit-1/actions" \
  "$PKG/usr/share/applications" "$PKG/usr/share/icons/hicolor/scalable/apps" \
  "$PKG/usr/share/doc/nova-x-desktop"

# The packaged control file must carry the same version as pyproject.toml, which
# also names the output artifact. Copying it verbatim let the two drift apart, so
# dpkg would install a file named for one version while recording another and
# silently break later upgrades.
sed "s/^Version:.*/Version: ${VERSION}/" "$ROOT/packaging/debian/control" > "$PKG/DEBIAN/control"
chmod 0644 "$PKG/DEBIAN/control"
CONTROL_VERSION="$(sed -n 's/^Version:[[:space:]]*//p' "$ROOT/packaging/debian/control" | head -n 1)"
if [ -n "$CONTROL_VERSION" ] && [ "$CONTROL_VERSION" != "$VERSION" ]; then
  echo "note: packaging/debian/control pins ${CONTROL_VERSION}; stamping ${VERSION} from pyproject.toml" >&2
fi
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
cat > "$PKG/usr/bin/nova-x-privileged-helper" <<'EOF'
#!/usr/bin/python3
import sys
sys.path.insert(0, "/usr/lib/nova-x")
from nova.system_access.helper_cli import main
raise SystemExit(main())
EOF
chmod 0755 "$PKG/usr/bin/nova-x-privileged-helper"
install -m 0644 "$ROOT/packaging/polkit/org.novax.pkexec.helper.policy" "$PKG/usr/share/polkit-1/actions/org.novax.pkexec.helper.policy"
install -m 0644 "$ROOT/packaging/debian/nova-x.desktop" "$PKG/usr/share/applications/nova-x.desktop"
install -m 0644 "$ROOT/packaging/debian/nova-x.svg" "$PKG/usr/share/icons/hicolor/scalable/apps/nova-x.svg"
install -m 0644 "$ROOT/packaging/debian/nova-x-worker.service" "$PKG/usr/lib/systemd/user/nova-x-worker.service"
install -m 0644 "$ROOT/packaging/debian/README.Debian" "$PKG/usr/share/doc/nova-x-desktop/README.Debian"
install -m 0644 "$ROOT/docs/NATIVE_DESKTOP.md" "$PKG/usr/share/doc/nova-x-desktop/README.native"
install -m 0644 "$ROOT/docs/UNIFIED_OS.md" "$PKG/usr/share/doc/nova-x-desktop/UNIFIED_OS.md"
install -m 0644 "$ROOT/docs/SYSTEM_ACCESS.md" "$PKG/usr/share/doc/nova-x-desktop/SYSTEM_ACCESS.md"
install -m 0644 "$ROOT/docs/PRIVACY_INTEL.md" "$PKG/usr/share/doc/nova-x-desktop/PRIVACY_INTEL.md"
install -m 0644 "$ROOT/README.md" "$PKG/usr/share/doc/nova-x-desktop/README.upstream"

install -d "$OUT_DIR"
OUT="$OUT_DIR/nova-x-desktop_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$PKG" "$OUT"
echo "Built: $OUT"
dpkg-deb --info "$OUT"
