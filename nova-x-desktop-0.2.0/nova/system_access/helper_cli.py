"""§152 Narrowly Scoped Privileged System Helper CLI (`nova-x-privileged-helper`).

Invoked cleanly via Polkit (`pkexec nova-x-privileged-helper <operation> <json_params>`)
when administrative hardware/driver/service changes are explicitly authorized.
Validates operations strictly against `DEFINED_HELPER_OPERATIONS` and refuses
arbitrary shell commands.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from nova.config import Settings
from nova.db import Database
from nova.observability import Redactor
from nova.system_access.privilege import DEFINED_HELPER_OPERATIONS, PrivilegedSystemHelper


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="nova-x-privileged-helper",
        description="NOVA X Narrowly Scoped Polkit Privileged Helper (§152)",
    )
    parser.add_argument("--list-operations", action="store_true", help="List defined allowlisted helper operations")
    parser.add_argument("--operation", default="", help="Allowlisted operation identifier")
    parser.add_argument("--params-json", default="{}", help="JSON object of validated operation parameters")
    parser.add_argument("--dry-run", action="store_true", help="Validate and preview argv without executing")
    args = parser.parse_args(argv)

    if args.list_operations:
        print(json.dumps({k: v.description for k, v in DEFINED_HELPER_OPERATIONS.items()}, indent=2))
        return 0

    if not args.operation:
        parser.error("--operation is required unless --list-operations is passed.")

    try:
        params = json.loads(args.params_json)
        if not isinstance(params, dict):
            raise ValueError("params-json must decode to a JSON object.")
    except ValueError as exc:
        print(json.dumps({"ok": False, "status": "invalid_json", "reason": str(exc)}))
        return 2

    settings = Settings.from_env()
    db = Database(Path(settings.db_path))
    db.initialize()
    helper = PrivilegedSystemHelper(db=db, redactor=Redactor())
    result = helper.execute_request(
        args.operation,
        params,
        requester="polkit_cli",
        operator_approved=True,
        dry_run=args.dry_run,
    )
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
