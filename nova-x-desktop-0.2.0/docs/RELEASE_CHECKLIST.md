# NOVA X Release Engineering Checklist & Compatibility Matrix (§104, §112)

## 1. Release Channels

| Channel | Identifier | Purpose & Promotion Policy |
|---|---|---|
| **Stable** | `stable` | Default operator channel. Accepts only verified semantic releases passing all CI gates, SHA-256 verification, DB migration checks, and launch probes. |
| **Candidate** | `candidate` | Staged pre-release builds (`X.Y.Z-rcN`) tested in `data/updates/candidates/` with an automatic SQLite + settings backup created beforehand. |
| **Development** | `development` | Working branch builds exercised by `pytest`, `ruff`, and `python -m nova.cognition`. Never auto-promoted to `stable`. |

> **Hard rules (§104):** Remote update scripts are never executed (`REMOTE_SCRIPT_EXECUTION = False`), unencrypted `http://` update manifests are rejected, and AI-proposed builds (`origin="ai_model"`) cannot replace the stable application directly.

---

## 2. Pre-Release Checklist

Run from `nova-x-desktop-0.2.0/`:

1. **Version parity:** Confirm `nova/__version__.py`, `pyproject.toml`, and `packaging/debian/control` agree on `X.Y.Z`.
2. **Static & syntax checks:**
   ```bash
   ruff check .
   python -m compileall -q nova tests app.py
   node --check static/app.js
   bash -n scripts/build_deb.sh
   ```
3. **Unit, security, regression & §114 integration matrix tests:**
   ```bash
   QT_QPA_PLATFORM=offscreen python -m pytest -q
   ```
4. **Offline general-intelligence evaluation gate (`nova-gie-v1`):**
   ```bash
   python -m nova.cognition --db /tmp/rel-gie.sqlite3 --workspace /tmp/rel-gie-ws
   python -m nova.cognition --include-held-out --db /tmp/rel-gie.sqlite3 --workspace /tmp/rel-gie-ws
   ```
5. **Debian artifact build & content verification:**
   ```bash
   bash scripts/build_deb.sh
   dpkg-deb --info releases/nova-x-desktop_*_all.deb
   ```
   Verify no `__pycache__`, `.pyc`, `.env`, or local SQLite files exist inside the archive, and compute `sha256sum releases/nova-x-desktop_*_all.deb`.
6. **Upgrade & rollback drill:**
   - Verify `UpdateManager.create_backup()` snapshots SQLite (`sqlite3.Connection.backup`) + desktop settings.
   - Verify `UpdateManager.check_migrations()` reports `ok: true` against an existing user database.
   - Confirm rollback instructions (`sudo dpkg -i nova-x-desktop_<prev>_all.deb` + `restore_backup()`) restore prior state cleanly.

---

## 3. Kali & Linux Desktop Compatibility Matrix

| Environment | Primary UI | Secret Storage | Execution Sandbox | Screen / Voice Modalities | Status & Notes |
|---|---|---|---|---|---|
| **Kali Linux Rolling (Xfce, X11)** — 2 cores / ~10 GB RAM target | Native `PySide6` window + `nova-x` CLI | `gnome-keyring` / Secret Service (`org.freedesktop.secrets`) | `bubblewrap` (`apt install bubblewrap`) or `unshare` user namespaces | Optional `scrot` + `tesseract-ocr` | **Primary target** (`NOVA_LOW_RESOURCE_MODE=true` default) |
| **Kali Linux Rolling (GNOME / KDE Wayland)** | Native `PySide6` (`wayland` / XWayland) + CLI | Secret Service (`gnome-keyring` / KWallet Secret Service) | `bubblewrap` or `unshare` user namespaces | Optional `grim` + `tesseract-ocr` | Supported; X11-only `scrot` replaced by `grim` |
| **Debian 12 / Ubuntu 24.04 LTS Desktop** | Native `PySide6` + CLI | Secret Service | `bubblewrap` (note: Ubuntu 24.04 `apparmor_restrict_unprivileged_userns=1` requires AppArmor-profiled `bwrap`; otherwise sandbox fails closed rather than running untrusted code on host) | Optional `grim`/`scrot` + `tesseract` | CI-tested (`ubuntu-latest`, Python 3.11–3.13) |
| **Headless Linux / Minimal Container (no `libGL`, no D-Bus)** | `nova-x` CLI + optional local HTTP UI | Keyring disabled safely (no plaintext fallback); env-only in server mode | `unshare` namespaces when kernel permits; otherwise `refused` fail-closed | Reported `unavailable` honestly; typed fallback active | Verified in automated test sandbox |
