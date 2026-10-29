"""Central, persistent autonomy policy and tool-action decisions.

The policy never grants a tool beyond its registry classification. Per-tool
"allow" rules are intentionally limited to tools marked routine, while
workspace overwrite authorization is always path-scoped.
"""
from __future__ import annotations

from pathlib import Path, PurePosixPath, PureWindowsPath
from tempfile import TemporaryDirectory
import time
from typing import Any
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from nova.config import Settings
from nova.db import Database
from nova.tools.registry import ToolRegistry


AUTONOMY_LEVELS: tuple[dict[str, str], ...] = (
    {
        "id": "assisted",
        "name": "A · Assisted",
        "description": "Plan first; ask before each tool action.",
        "availability": "available",
    },
    {
        "id": "routine",
        "name": "B · Routine autonomy",
        "description": "Run registered routine tools; pause for consequential or unclassified actions.",
        "availability": "available",
    },
    {
        "id": "advanced",
        "name": "C · Advanced",
        "description": "Configured, but currently limited to this installation's registered tool scopes.",
        "availability": "bounded",
    },
    {
        "id": "high",
        "name": "D · High autonomy",
        "description": "Configured, but does not unlock unimplemented integrations, schedulers, or high-impact actions.",
        "availability": "bounded",
    },
)

_VALID_LEVELS = {item["id"] for item in AUTONOMY_LEVELS}
_VALID_OVERRIDES = {"allow", "approve", "deny"}
_MAX_PATH_SCOPES = 20


class AutonomyPolicy:
    """Resolve and audit the active, user-configured autonomy policy."""

    def __init__(self, settings: Settings, database: Database, tools: ToolRegistry):
        self.settings = settings
        self.database = database
        self.tools = tools

    def get(self) -> dict[str, Any]:
        policy = self.database.get_autonomy_policy(self.settings.autonomy_level)
        return {
            **policy,
            "levels": [dict(level) for level in AUTONOMY_LEVELS],
            "capability_ceiling": "registered tools only; high-impact actions remain gated",
            "notice": (
                "Levels C and D do not add capabilities that are not installed. There is no always-on scheduler, "
                "email or public-posting tool, shell access, production deployment, or self-modifying policy."
            ),
        }

    def validate_update(
        self,
        level: str,
        tool_overrides: dict[str, str],
        authorized_overwrite_prefixes: list[str],
    ) -> tuple[dict[str, str], list[str]]:
        if level not in _VALID_LEVELS:
            raise ValueError("Choose one of the four listed autonomy levels.")
        if not isinstance(tool_overrides, dict) or len(tool_overrides) > 40:
            raise ValueError("Tool overrides must be an object with no more than 40 entries.")
        normalized_overrides: dict[str, str] = {}
        for raw_name, raw_action in tool_overrides.items():
            if not isinstance(raw_name, str) or self.tools.get(raw_name) is None:
                raise ValueError(f"Unknown tool in autonomy override: {raw_name!s}.")
            if raw_action not in _VALID_OVERRIDES:
                raise ValueError(f"Override for {raw_name} must be allow, approve, or deny.")
            tool = self.tools.get(raw_name)
            if raw_action == "allow" and tool and tool.autonomy_class != "routine":
                raise ValueError(f"'{raw_name}' is not classified as routine and cannot be automatically allowed.")
            normalized_overrides[raw_name] = raw_action

        if not isinstance(authorized_overwrite_prefixes, list) or len(authorized_overwrite_prefixes) > _MAX_PATH_SCOPES:
            raise ValueError(f"Use a list of at most {_MAX_PATH_SCOPES} workspace-relative overwrite scopes.")
        normalized_prefixes: list[str] = []
        for raw_prefix in authorized_overwrite_prefixes:
            if not isinstance(raw_prefix, str) or not raw_prefix.strip() or len(raw_prefix) > 200:
                raise ValueError("Each overwrite scope must be a non-empty workspace-relative path prefix of at most 200 characters.")
            raw = raw_prefix.strip().replace("\\", "/")
            pure = PurePosixPath(raw)
            windows = PureWindowsPath(raw)
            if (
                "\x00" in raw
                or pure.is_absolute()
                or windows.is_absolute()
                or windows.drive
                or any(part == ".." for part in raw.split("/"))
            ):
                raise ValueError("Overwrite scopes cannot be absolute paths or contain traversal components.")
            normalized = pure.as_posix().strip("/")
            if normalized in {"", "."}:
                raise ValueError("The entire workspace cannot be granted as an overwrite scope.")
            if normalized not in normalized_prefixes:
                normalized_prefixes.append(normalized)
        return normalized_overrides, normalized_prefixes

    def update(
        self,
        level: str,
        tool_overrides: dict[str, str],
        authorized_overwrite_prefixes: list[str],
    ) -> dict[str, Any]:
        normalized_overrides, normalized_prefixes = self.validate_update(
            level, tool_overrides, authorized_overwrite_prefixes
        )
        self.database.update_autonomy_policy(level, normalized_overrides, normalized_prefixes)
        return self.get()

    def decide(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        policy = self.database.get_autonomy_policy(self.settings.autonomy_level)
        tool = self.tools.get(tool_name)
        if tool is None:
            return {
                "action": "deny",
                "approved": False,
                "level": policy["level"],
                "rule": "tool_not_registered",
                "reason": "The requested tool is not registered.",
            }
        if not tool.available:
            return {
                "action": "deny",
                "approved": False,
                "level": policy["level"],
                "rule": "tool_unavailable",
                "reason": tool.unavailable_reason or "The tool is not configured.",
            }

        override = policy["tool_overrides"].get(tool_name)
        if override == "deny":
            return {
                "action": "deny", "approved": False, "level": policy["level"],
                "rule": "explicit_tool_deny", "reason": "This tool is disabled by your autonomy policy.",
            }
        if override == "approve":
            return {
                "action": "approval_required", "approved": False, "level": policy["level"],
                "rule": "explicit_tool_approval", "reason": "Your policy requires approval for this tool.",
            }

        if policy["level"] == "assisted" and override != "allow":
            return {
                "action": "approval_required", "approved": False, "level": policy["level"],
                "rule": "assisted_level", "reason": "Assisted mode requires approval before each tool action.",
            }
        if tool.autonomy_class != "routine" and override != "allow":
            return {
                "action": "approval_required", "approved": False, "level": policy["level"],
                "rule": "tool_requires_approval", "reason": "This tool is not classified for routine automatic execution.",
            }

        approved = False
        rule = "routine_tool"
        if tool_name == "workspace.write_file":
            path = arguments.get("path") if isinstance(arguments, dict) else None
            if isinstance(path, str) and self._within_authorized_scope(
                path, policy["authorized_overwrite_prefixes"]
            ):
                # The handler still validates the path, creates a backup and uses
                # race-safe file operations; this only authorizes replacement.
                approved = policy["level"] != "assisted" or override == "allow"
                if approved:
                    rule = "authorized_workspace_overwrite_scope"
        return {
            "action": "allow", "approved": approved, "level": policy["level"],
            "rule": rule,
            "reason": "Routine registered action is within the active policy." if not approved else "Workspace overwrite is covered by an explicit path-scoped authorization.",
        }

    @staticmethod
    def _within_authorized_scope(path: str, scopes: list[str]) -> bool:
        normalized = path.replace("\\", "/").strip("/")
        if not normalized or normalized.startswith("/") or "\x00" in normalized:
            return False
        parts = normalized.split("/")
        if any(part == ".." for part in parts):
            return False
        for scope in scopes:
            prefix = str(scope).replace("\\", "/").strip("/")
            if normalized == prefix or normalized.startswith(prefix + "/"):
                return True
        return False


async def run_autonomy_benchmark(settings: Settings) -> dict[str, Any]:
    """Run deterministic permission/scheduling checks in a temporary local sandbox.

    No model/provider request is made, and all file writes use a throwaway
    workspace rather than the operator's configured workspace.
    """
    from nova.tools import ToolRegistry, build_calculator_tool, build_workspace_tools

    started = time.perf_counter()
    cases: list[dict[str, Any]] = []
    with TemporaryDirectory(prefix="nova-autonomy-bench-") as temporary:
        root = Path(temporary)
        sandbox_settings = replace(
            settings,
            data_dir=root / "data",
            db_path=root / "data" / "benchmark.sqlite3",
            workspace_dir=root / "workspace",
        )
        sandbox_settings.ensure_dirs()
        database = Database(sandbox_settings.db_path)
        database.initialize()
        registry = ToolRegistry(sandbox_settings)
        registry.register(build_calculator_tool())
        for definition in build_workspace_tools(sandbox_settings):
            registry.register(definition)
        policy = AutonomyPolicy(sandbox_settings, database, registry)

        def record(case_id: str, passed: bool, detail: str) -> None:
            cases.append({"id": case_id, "status": "passed" if passed else "failed", "passed": bool(passed), "detail": detail})

        policy.update("assisted", {}, [])
        assisted = policy.decide("math.calculate", {"expression": "1 + 1"})
        record("assisted-requires-approval", assisted["action"] == "approval_required", assisted["rule"])

        policy.update("routine", {}, [])
        calculation_decision = policy.decide("math.calculate", {"expression": "6 * 7"})
        calculation = await registry.execute("math.calculate", {"expression": "6 * 7"}, approved=calculation_decision["approved"])
        record("routine-calculator-executes", calculation_decision["action"] == "allow" and calculation.status == "success" and calculation.data.get("value") == 42, calculation.status)

        workspace = sandbox_settings.workspace_dir
        existing = workspace / "existing.txt"
        existing.write_text("original", encoding="utf-8")
        write_args = {"path": "existing.txt", "content": "replacement"}
        gated_decision = policy.decide("workspace.write_file", write_args)
        gated = await registry.execute("workspace.write_file", write_args, approved=gated_decision["approved"])
        record("existing-file-requires-approval", gated.status == "approval_required" and existing.read_text(encoding="utf-8") == "original", gated.status)

        scoped_path = workspace / "bench"
        scoped_path.mkdir()
        scoped_file = scoped_path / "working.txt"
        scoped_file.write_text("before", encoding="utf-8")
        policy.update("routine", {}, ["bench"])
        scoped_args = {"path": "bench/working.txt", "content": "after"}
        scoped_decision = policy.decide("workspace.write_file", scoped_args)
        scoped = await registry.execute("workspace.write_file", scoped_args, approved=scoped_decision["approved"])
        backups = list((workspace / ".nova_backups").glob("*.bak"))
        backup_ok = any(item.read_text(encoding="utf-8") == "before" for item in backups)
        record("scoped-overwrite-backs-up", scoped_decision["approved"] and scoped.status == "success" and scoped_file.read_text(encoding="utf-8") == "after" and backup_ok, scoped.status)

        policy.update("routine", {"math.calculate": "deny"}, [])
        denied = policy.decide("math.calculate", {"expression": "1 + 1"})
        record("explicit-deny-wins", denied["action"] == "deny" and denied["rule"] == "explicit_tool_deny", denied["rule"])
        unknown = policy.decide("unregistered.tool", {})
        record("unknown-tools-are-blocked", unknown["action"] == "deny", unknown["rule"])

        goal = database.create_goal("Benchmark goal", "A user-configured test objective", 60, enabled=False)
        future = datetime.now(timezone.utc) + timedelta(days=3)
        no_dispatch = database.dispatch_due_goals(daily_limit=5, now=future)
        database.update_goal(goal["id"], enabled=True)
        dispatched = database.dispatch_due_goals(daily_limit=5, now=future)
        goal_ok = not no_dispatch and len(dispatched) == 1 and dispatched[0]["goal_id"] == goal["id"]
        record("only-enabled-configured-goals-dispatch", goal_ok, "disabled goals skipped; enabled goal produced one bounded task" if goal_ok else "unexpected schedule dispatch")

    passed = sum(item["passed"] for item in cases)
    return {
        "suite": "nova-autonomy-policy-v1",
        "status": "passed" if passed == len(cases) else "failed",
        "passed": passed,
        "total": len(cases),
        "score_percent": round((passed / len(cases)) * 100) if cases else 0,
        "provider_requests": 0,
        "external_requests": 0,
        "isolated_temporary_workspace": True,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "cases": cases,
        "limitations": "Deterministic permission/scheduler regression suite only; does not measure model truth, reasoning quality, live provider access, hosting uptime, or production safety.",
    }
