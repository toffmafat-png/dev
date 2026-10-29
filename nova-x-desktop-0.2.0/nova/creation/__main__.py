"""CLI runner for §148 Universal Creation Capability Test (`python -m nova.creation`)."""
from __future__ import annotations

import argparse
import asyncio
import json
import tempfile
from dataclasses import replace
from pathlib import Path

from nova.autonomy import AutonomyPolicy
from nova.config import Settings
from nova.db import Database
from nova.platform_service import PlatformService
from nova.tools import ToolRegistry, build_calculator_tool, build_workspace_tools


def _prepare_platform(db_path: Path, workspace_dir: Path) -> PlatformService:
    base = Settings.from_env()
    data_dir = db_path.parent
    data_dir.mkdir(parents=True, exist_ok=True)
    workspace_dir.mkdir(parents=True, exist_ok=True)
    settings = replace(
        base,
        data_dir=data_dir.resolve(),
        db_path=db_path.resolve(),
        workspace_dir=workspace_dir.resolve(),
        low_resource_mode=True,
    )
    db = Database(settings.db_path)
    db.initialize()
    registry = ToolRegistry(settings)
    registry.register(build_calculator_tool())
    for tool_def in build_workspace_tools(settings):
        registry.register(tool_def)
    policy = AutonomyPolicy(settings, db, registry)
    return PlatformService(settings=settings, db=db, tools=registry, autonomy_policy=policy)


async def _run(platform: PlatformService, json_output: bool) -> int:
    result = await platform.creation.run_capability_suite()
    if json_output:
        print(json.dumps(result, indent=2))
    else:
        print(f"NOVA X Universal Creation Capability Test ({result['suite_version']}): {result['passed_cases']}/{result['total_cases']} passed")
        for case in result["cases"]:
            mark = "PASS" if case["passed"] else "FAIL"
            print(f"  [{mark}] {case['id']} ({case['domain']}) -> {len(case['files_produced'])} artifact(s) via {', '.join(case['tools_used'][:3])}")
            for lim in case.get("limitations", [])[:1]:
                print(f"         limitation: {lim}")
    return 0 if result["all_demonstrated_passed"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run NOVA X §148 Universal Creation Capability Test.")
    parser.add_argument("--db", default="", help="SQLite DB path (defaults to temporary run DB)")
    parser.add_argument("--workspace", default="", help="Workspace directory (defaults to temporary workspace)")
    parser.add_argument("--json", action="store_true", help="Emit full JSON suite report")
    args = parser.parse_args(argv)

    if args.db and args.workspace:
        plat = _prepare_platform(Path(args.db), Path(args.workspace))
        return asyncio.run(_run(plat, args.json))

    with tempfile.TemporaryDirectory(prefix="nova-uce-") as tmp:
        root = Path(tmp)
        db_p = Path(args.db) if args.db else (root / "state" / "nova.sqlite3")
        ws_p = Path(args.workspace) if args.workspace else (root / "workspace")
        plat = _prepare_platform(db_p, ws_p)
        return asyncio.run(_run(plat, args.json))


if __name__ == "__main__":
    raise SystemExit(main())
