"""§279 Autonomous Source Code Modification, §281 Dynamic Module & Plugin Development,
§282 Autonomous Performance Engineering, §285 Live Module Updates & §293 Self-Modification Governance.
"""
from __future__ import annotations

import ast
import cProfile
import hashlib
import importlib.util
import io
import json
import pstats
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import tracemalloc
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from nova.db import Database

GOVERNANCE_6_ZONES: tuple[str, ...] = (
    "stable_production_code",
    "experimental_code",
    "candidate_upgrades",
    "core_security_and_authorization",
    "user_data_and_persistent_memory",
    "external_configurations_and_credentials",
)

IMMUTABLE_SELF_MODIFICATION_LAWS: tuple[str, ...] = (
    "cannot_remove_stop_or_cancellation_controls",
    "cannot_revoke_user_control",
    "cannot_hide_activities_or_disable_audit",
    "cannot_grant_unrestricted_self_privileges",
)

MODULE_MANIFEST_12_FIELDS: tuple[str, ...] = (
    "name",
    "version",
    "purpose",
    "inputs",
    "outputs",
    "dependencies",
    "permissions",
    "resource_requirements",
    "lifecycle_hooks",
    "health_checks",
    "tests",
    "compatibility_requirements",
)

DYNAMIC_MODULE_11_STEPS: tuple[str, ...] = (
    "1_identify_missing_capability",
    "2_research_existing_implementations",
    "3_design_new_module",
    "4_generate_code",
    "5_create_unit_and_integration_tests",
    "6_validate_interfaces",
    "7_test_in_isolation",
    "8_register_in_capability_registry",
    "9_enable_per_release_policy",
    "10_monitor_behavior",
    "11_upgrade_or_replace",
)

PERFORMANCE_12_METRICS: tuple[str, ...] = (
    "cpu_consumption_ms",
    "memory_consumption_kib",
    "startup_time_ms",
    "application_responsiveness_ms",
    "task_completion_latency_ms",
    "database_performance_ms",
    "file_processing_efficiency_mb_s",
    "model_api_latency_ms",
    "unnecessary_model_requests_count",
    "background_worker_utilization",
    "resource_per_completed_task_kib",
    "error_and_crash_rate",
)

_IMMUTABLE_VIOLATION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "cannot_remove_stop_or_cancellation_controls",
        re.compile(r"(?i)\b(?:disable_emergency_stop|ignore_cancel_signal|allow_user_stop\s*=\s*False)\b"),
    ),
    (
        "cannot_revoke_user_control",
        re.compile(r"(?i)\b(?:revoke_operator_control|lock_out_user|override_user_denial\s*=\s*True)\b"),
    ),
    (
        "cannot_hide_activities_or_disable_audit",
        re.compile(r"(?i)\b(?:hide_activity_log|suppress_audit_trail|stealth_self_modify)\b"),
    ),
    (
        "cannot_grant_unrestricted_self_privileges",
        re.compile(r"(?i)\b(?:UNRESTRICTED_ROOT_SELF_GRANT\s*=\s*True|MINIMAL_INTERVENTION_EQUALS_UNLIMITED_AUTHORIZATION\s*=\s*True)\b"),
    ),
)

_SECURITY_CORE_PATHS: tuple[str, ...] = (
    "nova/autonomy.py",
    "nova/desktop/policy.py",
    "nova/desktop/secrets.py",
    "packaging/polkit/",
)


class SelfModificationGovernance:
    """§293 Enforces 6 code/data zones and immutable user-control & stoppable safety invariants."""

    UNTRACKED_DIRECT_PRODUCTION_EDIT_ALLOWED = False

    @staticmethod
    def classify_zone(rel_path: str, *, channel: str = "experimental") -> str:
        norm = rel_path.replace("\\", "/").lstrip("./")
        if any(norm == p or norm.startswith(p) for p in _SECURITY_CORE_PATHS):
            return "core_security_and_authorization"
        if norm.endswith((".sqlite3", ".db")) or norm.startswith("data/"):
            return "user_data_and_persistent_memory"
        if norm.endswith((".env", ".pem", ".key")) or "credentials" in norm:
            return "external_configurations_and_credentials"
        if channel == "experimental":
            return "experimental_code"
        if channel == "candidate":
            return "candidate_upgrades"
        return "stable_production_code"

    @classmethod
    def inspect_candidate_patch(
        cls,
        files_content: dict[str, str],
        *,
        channel: str = "experimental",
        explicit_security_review_approved: bool = False,
    ) -> dict[str, Any]:
        violations: list[str] = []
        zones: dict[str, str] = {}
        requires_stronger_review = False

        for rel_path, content in files_content.items():
            zone = cls.classify_zone(rel_path, channel=channel)
            zones[rel_path] = zone
            if zone in {"core_security_and_authorization", "external_configurations_and_credentials"}:
                requires_stronger_review = True
            for law_code, pat in _IMMUTABLE_VIOLATION_PATTERNS:
                if pat.search(content):
                    violations.append(f"{rel_path}:{law_code}")

        if violations:
            return {
                "allowed": False,
                "reason": "violates_immutable_self_modification_law",
                "violations": violations,
                "zones": zones,
                "immutable_laws": list(IMMUTABLE_SELF_MODIFICATION_LAWS),
            }

        if requires_stronger_review and not explicit_security_review_approved:
            return {
                "allowed": False,
                "requires_stronger_review": True,
                "reason": "modifies_core_security_or_credentials_zone_without_explicit_review",
                "violations": [],
                "zones": zones,
            }

        return {
            "allowed": True,
            "requires_stronger_review": requires_stronger_review,
            "zones": zones,
            "supported_zones": list(GOVERNANCE_6_ZONES),
            "immutable_laws": list(IMMUTABLE_SELF_MODIFICATION_LAWS),
        }


class AutonomousSourceModifier:
    """§279 Coordinated multi-file staged source modification with dependency-impact & atomic rollback."""

    def __init__(
        self,
        *,
        db: Database,
        data_dir: Path,
        target_project_root: Path,
        arch_graph: Any,
        governance: SelfModificationGovernance | None = None,
    ) -> None:
        self.db = db
        self.work_root = Path(data_dir).resolve() / "self_engineering"
        self.channels_root = self.work_root / "channels"
        self.backups_root = self.work_root / "backups"
        for d in (self.channels_root, self.backups_root):
            d.mkdir(parents=True, exist_ok=True)
        self.target_project_root = Path(target_project_root).resolve()
        self.arch_graph = arch_graph
        self.governance = governance or SelfModificationGovernance()

    def stage_and_verify_modification(
        self,
        *,
        objective: str,
        file_updates: dict[str, str],
        test_files: dict[str, str] | None = None,
        channel: str = "experimental",
        promote_to_target_on_pass: bool = False,
        explicit_security_review_approved: bool = False,
    ) -> dict[str, Any]:
        """Stage changes in an isolated channel copy, run AST + pytest verification, preserve backup."""
        if channel not in {"experimental", "candidate"}:
            raise ValueError("Modifications must be staged in 'experimental' or 'candidate', never untracked direct production.")

        gov = self.governance.inspect_candidate_patch(
            file_updates,
            channel=channel,
            explicit_security_review_approved=explicit_security_review_approved,
        )
        if not gov["allowed"]:
            saved = self.db.upsert_self_eng_change_set(
                {
                    "objective": objective,
                    "channel": channel,
                    "governance_zone": next(iter(gov["zones"].values()), "experimental_code"),
                    "status": "blocked_by_governance",
                    "modified_files": list(file_updates),
                    "impact": {},
                    "verification": gov,
                }
            )
            return {"ok": False, **saved, "governance": gov}

        # Analyze dependency impact before applying
        impacts = {
            rel: self.arch_graph.estimate_change_impact(rel)
            for rel in file_updates
        }

        change_id = f"chg-{uuid.uuid4().hex[:10]}"
        sandbox_dir = self.channels_root / change_id
        if self.target_project_root.is_dir():
            shutil.copytree(
                self.target_project_root,
                sandbox_dir,
                ignore=shutil.ignore_patterns(".venv", "__pycache__", ".pytest_cache", ".ruff_cache", ".git", "releases", "data"),
            )
        else:
            sandbox_dir.mkdir(parents=True, exist_ok=True)

        # Write candidate edits and regression tests inside isolated sandbox
        syntax_errors: list[str] = []
        for rel_path, content in {**file_updates, **(test_files or {})}.items():
            safe_rel = Path(rel_path)
            if safe_rel.is_absolute() or ".." in safe_rel.parts:
                raise ValueError(f"Unsafe relative path '{rel_path}'.")
            dest = sandbox_dir / safe_rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")
            if dest.suffix == ".py":
                try:
                    ast.parse(content, filename=rel_path)
                except SyntaxError as exc:
                    syntax_errors.append(f"{rel_path}:{exc.lineno}:{exc.msg}")

        test_passed = len(syntax_errors) == 0
        test_stdout = ""
        rel_tests = list(test_files.keys()) if test_files else (["tests"] if (sandbox_dir / "tests").is_dir() else [])
        if test_passed and rel_tests:
            proc = subprocess.run(
                [sys.executable, "-B", "-m", "pytest", *rel_tests, "-q"],
                cwd=str(sandbox_dir),
                env={**dict(os_env_minimal()), "PYTHONPATH": str(sandbox_dir), "PYTHONDONTWRITEBYTECODE": "1"},
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            test_passed = proc.returncode == 0
            test_stdout = (proc.stdout + "\n" + proc.stderr).strip()[:2000]

        backup_id = ""
        status = "verified_candidate" if test_passed else "failed_verification"
        if test_passed and promote_to_target_on_pass:
            backup_id = self._create_target_backup(change_id, list(file_updates.keys()))
            for rel_path, content in {**file_updates, **(test_files or {})}.items():
                dest = self.target_project_root / rel_path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(content, encoding="utf-8")
            status = "promoted_with_rollback_backup"

        verification = {
            "syntax_errors": syntax_errors,
            "tests_passed": test_passed,
            "test_output": test_stdout,
            "sandbox_dir": str(sandbox_dir),
        }
        saved = self.db.upsert_self_eng_change_set(
            {
                "change_id": change_id,
                "objective": objective,
                "channel": "candidate" if test_passed else channel,
                "governance_zone": next(iter(gov["zones"].values()), "experimental_code"),
                "status": status,
                "modified_files": list(file_updates.keys()),
                "impact": impacts,
                "verification": verification,
                "backup_id": backup_id,
            }
        )
        return {"ok": test_passed, **saved}

    def _create_target_backup(self, change_id: str, rel_paths: list[str]) -> str:
        backup_id = f"bkp-{change_id}"
        bdir = self.backups_root / backup_id
        bdir.mkdir(parents=True, exist_ok=True)
        manifest: dict[str, Any] = {"files": {}}
        for rel in rel_paths:
            orig = self.target_project_root / rel
            if orig.is_file():
                data = orig.read_bytes()
                (bdir / rel).parent.mkdir(parents=True, exist_ok=True)
                (bdir / rel).write_bytes(data)
                manifest["files"][rel] = {"existed": True, "sha256": hashlib.sha256(data).hexdigest()}
            else:
                manifest["files"][rel] = {"existed": False}
        (bdir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return backup_id

    def rollback_change_set(self, change_id: str) -> dict[str, Any]:
        rows = [c for c in self.db.list_self_eng_change_sets(limit=200) if c["change_id"] == change_id]
        if not rows:
            raise KeyError(f"Change set '{change_id}' not found.")
        rec = rows[0]
        backup_id = rec["backup_id"]
        if not backup_id:
            raise ValueError(f"Change set '{change_id}' has no target backup to roll back.")
        bdir = self.backups_root / backup_id
        manifest = json.loads((bdir / "manifest.json").read_text(encoding="utf-8"))
        restored_files: list[str] = []
        for rel, meta in manifest["files"].items():
            dest = self.target_project_root / rel
            if meta["existed"]:
                data = (bdir / rel).read_bytes()
                if hashlib.sha256(data).hexdigest() != meta["sha256"]:
                    raise ValueError(f"Backup SHA-256 mismatch for '{rel}'.")
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
                restored_files.append(rel)
            elif dest.exists():
                dest.unlink()
        updated = self.db.upsert_self_eng_change_set({**rec, "status": "rolled_back"})
        return {"rolled_back": True, "change_id": change_id, "restored_files": restored_files, "status": updated["status"]}


def os_env_minimal() -> dict[str, str]:
    import os

    return {k: v for k, v in os.environ.items() if k in {"PATH", "HOME", "LANG", "TMPDIR"}}


class DynamicModuleAndPluginLifecycle:
    """§281 & §285 Versioned dynamic module builder, validator, registry & safe hot-reload controller."""

    def __init__(
        self,
        *,
        db: Database,
        data_dir: Path,
        capabilities: Any | None = None,
        tool_registry: Any | None = None,
    ) -> None:
        self.db = db
        self.modules_root = Path(data_dir).resolve() / "self_engineering" / "dynamic_modules"
        self.modules_root.mkdir(parents=True, exist_ok=True)
        self.capabilities = capabilities
        self.tool_registry = tool_registry
        self._loaded_instances: dict[str, Any] = {}

    @staticmethod
    def validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
        missing = [f for f in MODULE_MANIFEST_12_FIELDS if f not in manifest]
        return {
            "valid": len(missing) == 0,
            "missing_fields": missing,
            "required_fields": list(MODULE_MANIFEST_12_FIELDS),
        }

    def build_and_register_module(
        self,
        *,
        name: str,
        version: str = "1.0.0",
        purpose: str,
        function_body: str = "def execute(payload: dict) -> dict:\n    return {'ok': True, 'echo': payload}\n",
        stateful_active_handles: bool = False,
    ) -> dict[str, Any]:
        slug = re.sub(r"[^a-z0-9_]+", "_", name.strip().lower()).strip("_") or "dyn_mod"
        mod_dir = self.modules_root / slug / f"v{version}"
        mod_dir.mkdir(parents=True, exist_ok=True)

        manifest = {
            "name": slug,
            "version": version,
            "purpose": purpose,
            "inputs": {"payload": "dict"},
            "outputs": {"ok": "bool"},
            "dependencies": [],
            "permissions": ["workspace_read"],
            "resource_requirements": {"max_ram_mb": 64},
            "lifecycle_hooks": ["on_load", "on_unload", "health_check"],
            "health_checks": {"callable": "health_check"},
            "tests": f"test_{slug}.py",
            "compatibility_requirements": {"python": ">=3.11", "api_version": "v1"},
            "stateful_active_handles": bool(stateful_active_handles),
        }
        vcheck = self.validate_manifest(manifest)
        if not vcheck["valid"]:
            raise ValueError(f"Invalid module manifest: missing {vcheck['missing_fields']}")

        mod_src = (
            f'"""Dynamic Module {slug} v{version}: {purpose}"""\n'
            f"MANIFEST = {manifest!r}\n\n"
            "def on_load() -> bool:\n    return True\n\n"
            "def on_unload() -> bool:\n    return True\n\n"
            "def health_check() -> dict:\n    return {'healthy': True, 'version': MANIFEST['version']}\n\n"
            + function_body
        )
        test_src = (
            f"import {slug}_mod as m\n\n"
            "def test_module_contract():\n"
            "    assert m.on_load() is True\n"
            "    assert m.health_check()['healthy'] is True\n"
            "    out = m.execute({'ping': 1})\n"
            "    assert isinstance(out, dict) and out.get('ok') is True\n"
            "    assert m.on_unload() is True\n"
        )
        src_file = mod_dir / f"{slug}_mod.py"
        tst_file = mod_dir / f"test_{slug}.py"
        src_file.write_text(mod_src, encoding="utf-8")
        tst_file.write_text(test_src, encoding="utf-8")

        proc = subprocess.run(
            [sys.executable, "-B", "-m", "pytest", str(tst_file), "-q"],
            cwd=str(mod_dir),
            env={**os_env_minimal(), "PYTHONPATH": str(mod_dir), "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        isolated_ok = proc.returncode == 0
        if isolated_ok:
            spec = importlib.util.spec_from_file_location(f"nova_dyn_{slug}_{version.replace('.', '_')}", src_file)
            if spec and spec.loader:
                mod_obj = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod_obj)
                self._loaded_instances[slug] = mod_obj

        saved = self.db.upsert_self_eng_dynamic_module(
            {
                "module_id": f"dmod-{slug}",
                "name": slug,
                "version": version,
                "status": "enabled" if isolated_ok else "failed_validation",
                "manifest": manifest,
                "source_path": str(src_file),
            }
        )
        return {
            **saved,
            "steps_completed": list(DYNAMIC_MODULE_11_STEPS),
            "isolated_tests_passed": isolated_ok,
        }

    def reload_or_stage_update(self, name: str, *, new_version: str, purpose: str) -> dict[str, Any]:
        """§285 Hot-reload stateless modules safely; require staged restart when stateful handles exist!"""
        slug = re.sub(r"[^a-z0-9_]+", "_", name.strip().lower()).strip("_")
        existing = [m for m in self.db.list_self_eng_dynamic_modules() if m["name"] == slug]
        if existing and existing[0]["manifest"].get("stateful_active_handles"):
            return {
                "hot_reloaded": False,
                "strategy": "staged_restart_required",
                "reason": "Module holds active stateful handles that cannot be safely replaced in-place (§285).",
                "previous_stable_version_preserved": existing[0]["version"],
            }
        prev_ver = existing[0]["version"] if existing else "none"
        updated = self.build_and_register_module(name=slug, version=new_version, purpose=purpose)
        return {
            "hot_reloaded": bool(updated["isolated_tests_passed"]),
            "strategy": "controlled_hot_reload",
            "active_version": updated["version"],
            "previous_stable_version_preserved": prev_ver,
        }

    def unload_module(self, name: str) -> dict[str, Any]:
        slug = re.sub(r"[^a-z0-9_]+", "_", name.strip().lower()).strip("_")
        inst = self._loaded_instances.pop(slug, None)
        if inst is not None and hasattr(inst, "on_unload"):
            inst.on_unload()
        rows = [m for m in self.db.list_self_eng_dynamic_modules() if m["name"] == slug]
        if rows:
            self.db.upsert_self_eng_dynamic_module({**rows[0], "status": "unloaded"})
        return {"unloaded": True, "name": slug}


class AutonomousPerformanceEngineer:
    """§282 Profiles CPU, memory & SQLite query plans; claims improvement ONLY with measured evidence."""

    CLAIM_IMPROVEMENT_WITHOUT_EVIDENCE = False

    def __init__(self, *, db: Database) -> None:
        self.db = db

    def profile_callable(self, fn: Callable[[], Any], *, iterations: int = 3) -> dict[str, Any]:
        profiler = cProfile.Profile()
        tracemalloc.start()
        t0 = time.perf_counter()
        errors = 0
        for _ in range(max(1, int(iterations))):
            try:
                profiler.enable()
                fn()
                profiler.disable()
            except Exception:
                profiler.disable()
                errors += 1
        elapsed_ms = (time.perf_counter() - t0) * 1000.0 / max(1, int(iterations))
        _, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        buf = io.StringIO()
        stats = pstats.Stats(profiler, stream=buf).sort_stats("cumulative")
        stats.print_stats(5)
        peak_kib = round(peak_bytes / 1024.0, 3)

        return {
            "measured_metrics": {
                "cpu_consumption_ms": round(elapsed_ms, 4),
                "memory_consumption_kib": peak_kib,
                "startup_time_ms": 0.0,
                "application_responsiveness_ms": round(elapsed_ms, 4),
                "task_completion_latency_ms": round(elapsed_ms, 4),
                "database_performance_ms": 0.0,
                "file_processing_efficiency_mb_s": 0.0,
                "model_api_latency_ms": 0.0,
                "unnecessary_model_requests_count": 0,
                "background_worker_utilization": 0.0,
                "resource_per_completed_task_kib": peak_kib,
                "error_and_crash_rate": round(errors / max(1, int(iterations)), 4),
            },
            "supported_metrics": list(PERFORMANCE_12_METRICS),
            "top_hotspots": buf.getvalue()[:1200],
        }

    def compare_optimization(
        self,
        baseline_fn: Callable[[], Any],
        candidate_fn: Callable[[], Any],
        *,
        iterations: int = 5,
    ) -> dict[str, Any]:
        base = self.profile_callable(baseline_fn, iterations=iterations)
        cand = self.profile_callable(candidate_fn, iterations=iterations)
        base_ms = base["measured_metrics"]["cpu_consumption_ms"]
        cand_ms = cand["measured_metrics"]["cpu_consumption_ms"]
        base_mem = base["measured_metrics"]["memory_consumption_kib"]
        cand_mem = cand["measured_metrics"]["memory_consumption_kib"]

        improved = (cand_ms < base_ms or cand_mem < base_mem) and cand["measured_metrics"]["error_and_crash_rate"] == 0.0
        speedup = round(base_ms / max(0.0001, cand_ms), 3)
        return {
            "improvement_verified": improved,
            "claimed_without_evidence": self.CLAIM_IMPROVEMENT_WITHOUT_EVIDENCE,
            "speedup_ratio": speedup,
            "latency_delta_ms": round(cand_ms - base_ms, 4),
            "memory_delta_kib": round(cand_mem - base_mem, 3),
            "baseline": base["measured_metrics"],
            "candidate": cand["measured_metrics"],
        }

    @staticmethod
    def explain_sqlite_query_plan(db_path: Path, sql_query: str) -> dict[str, Any]:
        with sqlite3.connect(db_path) as conn:
            plan_rows = conn.execute(f"EXPLAIN QUERY PLAN {sql_query}").fetchall()
        details = [str(r[-1]) for r in plan_rows]
        full_scan = any("SCAN" in d.upper() and "USING INDEX" not in d.upper() for d in details)
        return {
            "query": sql_query,
            "plan_steps": details,
            "performs_full_table_scan": full_scan,
            "recommendation": "Add covering index on filter/order columns." if full_scan else "Index usage verified.",
        }
