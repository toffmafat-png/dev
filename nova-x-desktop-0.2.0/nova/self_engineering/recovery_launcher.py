"""§288 Standalone minimal-dependency Recovery Launcher (`python -m nova.self_engineering.recovery_launcher`).

Designed to run with Python's standard library alone so that if the main desktop/Qt/FastAPI
application fails to start due to a broken candidate upgrade or interrupted update, DEV can
still inspect transaction journals, verify SQLite integrity, and restore the known-good stable release.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def run_standalone_recovery(
    *,
    data_dir: Path,
    db_path: Path | None = None,
    restore_version: str = "",
) -> dict[str, Any]:
    root = Path(data_dir).resolve()
    rel_root = root / "self_engineering" / "releases"
    channels_dir = rel_root / "channels"
    journal_path = rel_root / "update_transaction_journal.json"

    report: dict[str, Any] = {
        "launcher": "nova.self_engineering.recovery_launcher",
        "stdlib_only": True,
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "interrupted_update_recovered": False,
        "restored_stable_version": "",
        "sqlite_integrity": "not_checked",
    }

    if journal_path.is_file():
        jdata = json.loads(journal_path.read_text(encoding="utf-8"))
        if jdata.get("in_progress"):
            prev = str(jdata.get("previous_stable") or "")
            if prev and (channels_dir / "stable" / f"v{prev}").is_dir():
                (channels_dir / "stable" / "ACTIVE_VERSION").write_text(prev, encoding="utf-8")
                report["restored_stable_version"] = prev
            jdata["in_progress"] = False
            jdata["recovered_by_launcher"] = True
            journal_path.write_text(json.dumps(jdata, indent=2), encoding="utf-8")
            report["interrupted_update_recovered"] = True

    if restore_version:
        target = channels_dir / "stable" / f"v{restore_version}"
        if not target.is_dir():
            raise FileNotFoundError(f"Stable version v{restore_version} not found under {channels_dir / 'stable'}")
        (channels_dir / "stable" / "ACTIVE_VERSION").write_text(restore_version, encoding="utf-8")
        report["restored_stable_version"] = restore_version

    target_db = Path(db_path) if db_path else (root / "nova.db")
    if target_db.is_file():
        with sqlite3.connect(target_db) as conn:
            report["sqlite_integrity"] = str(conn.execute("PRAGMA integrity_check").fetchone()[0])

    active_ptr = channels_dir / "stable" / "ACTIVE_VERSION"
    report["active_stable_version"] = active_ptr.read_text(encoding="utf-8").strip() if active_ptr.is_file() else ""
    report["ok"] = report["sqlite_integrity"] in {"ok", "not_checked"}
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="DEV Standalone Self-Repair & Recovery Launcher (§288)")
    parser.add_argument("--data-dir", default="./data", help="Path to DEV runtime data directory")
    parser.add_argument("--db-path", default="", help="Optional explicit SQLite DB path")
    parser.add_argument("--restore-stable", default="", help="Known-good stable version to restore")
    args = parser.parse_args(argv)

    rep = run_standalone_recovery(
        data_dir=Path(args.data_dir),
        db_path=Path(args.db_path) if args.db_path else None,
        restore_version=args.restore_stable,
    )
    print(json.dumps(rep, indent=2, sort_keys=True))
    return 0 if rep.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
