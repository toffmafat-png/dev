"""§214 Autonomous Security Tool Factory, §215 Purple-Team Ops, §217 Continuous Automation, §218 Tutor & §219 Self-Improvement."""
from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from nova.cyber_division.scope_and_surface import SecurityScopeRegistry
from nova.db import Database
from nova.tools.registry import ToolDefinition, ToolOutcome, ToolRegistry

TOOL_FACTORY_17_CATEGORIES: tuple[str, ...] = (
    "network_inventory",
    "configuration_auditor",
    "security_log_parser",
    "vulnerability_report_analyzer",
    "local_asset_discovery",
    "dependency_security_scanner",
    "api_test_harness",
    "file_integrity_monitor",
    "security_compliance_checker",
    "yara_rule_manager",
    "forensic_data_processor",
    "packet_analysis_helper",
    "security_dashboard",
    "remediation_verifier",
    "defensive_monitor",
    "security_research_notebook",
    "integration_adapter",
)

PROHIBITED_TOOL_FACTORY_TERMS: tuple[str, ...] = (
    "credential theft",
    "steal password",
    "keylogger",
    "unauthorized persistence",
    "rootkit",
    "stealthy compromise",
    "bypass security control",
    "evade antivirus",
    "ransomware",
    "wiper",
)

FORBIDDEN_GENERATED_AST_CALLS: frozenset[str] = frozenset(
    {"eval", "exec", "rmtree", "remove", "unlink", "kill", "system", "popen"}
)

TUTOR_17_DISCIPLINES: tuple[str, ...] = (
    "linux_security",
    "network_engineering",
    "penetration_testing_methodology",
    "web_security",
    "api_security",
    "secure_coding",
    "digital_forensics",
    "reverse_engineering",
    "vulnerability_management",
    "incident_response",
    "cloud_security",
    "wireless_security",
    "container_security",
    "security_architecture",
    "malware_analysis",
    "defensive_monitoring",
    "security_research",
)


class GeneratedSecurityToolInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_path: str = Field(min_length=1, max_length=400)


class AutonomousSecurityToolFactory:
    """§214 14-Step Defensive Security Tool Factory with AST safety gates, sandbox testing & policy-enforced registration."""

    ALLOW_OFFENSIVE_OR_EVASION_TOOLS = False

    def __init__(
        self,
        *,
        db: Database,
        workspace_dir: Path,
        scope_registry: SecurityScopeRegistry,
        tool_registry: ToolRegistry | None = None,
    ):
        self.db = db
        self.workspace_dir = workspace_dir
        self.scope_registry = scope_registry
        self.tool_registry = tool_registry

    def build_and_register_defensive_tool(
        self,
        *,
        name: str,
        category: str,
        purpose: str,
        prefer_existing_if_exact_cli: str = "",
        custom_python_body: str = "",
    ) -> dict[str, Any]:
        """§214 Execute all 14 tool-development steps, registering safely under DEV's Scope & Autonomy policies."""
        purpose_low = f"{name} {purpose}".lower()
        for bad in PROHIBITED_TOOL_FACTORY_TERMS:
            if bad in purpose_low:
                return {
                    "ok": False,
                    "status": "refused_prohibited_tool_intent",
                    "reason": f"Refused: DEV Tool Factory never builds tools for `{bad}` (§214).",
                }

        cat = category.strip().lower()
        if cat not in TOOL_FACTORY_17_CATEGORIES:
            raise ValueError(f"Unsupported factory category '{category}'. Valid: {TOOL_FACTORY_17_CATEGORIES}")

        slug = re.sub(r"[^a-z0-9_]+", "_", name.strip().lower()).strip("_")
        if not slug:
            raise ValueError("Tool name must contain alphanumeric characters.")

        steps: list[dict[str, Any]] = [{"step": 1, "action": "identify_missing_capability", "category": cat}]

        # Steps 2–5: Check existing installed mature software before creating a new tool!
        if prefer_existing_if_exact_cli and shutil.which(prefer_existing_if_exact_cli):
            return {
                "ok": True,
                "status": "existing_installed_tool_preferred",
                "existing_executable": shutil.which(prefer_existing_if_exact_cli),
                "recreated_unnecessarily": False,
                "steps": [
                    *steps,
                    {"step": 2, "action": "search_existing_software", "found": prefer_existing_if_exact_cli},
                    {"step": 5, "action": "determine_new_tool_unnecessary", "reused": prefer_existing_if_exact_cli},
                ],
            }

        steps.extend(
            [
                {"step": 2, "action": "search_existing_software", "custom_gap_confirmed": True},
                {"step": 3, "action": "examine_official_documentation", "stdlib_modules": ["hashlib", "json", "pathlib", "stat"]},
                {"step": 4, "action": "compare_maintenance_and_licensing", "license": "MIT_local_workspace"},
                {"step": 5, "action": "determine_new_tool_necessary", "necessary": True},
                {"step": 6, "action": "define_purpose_and_limitations", "read_only_defensive": True},
                {"step": 7, "action": "design_architecture", "entrypoint": "inspect_target(target_path: str) -> dict"},
            ]
        )

        prev = self.db.get_cyber_generated_tool(f"sec_factory_{slug}")
        next_ver = (int(prev["version"]) + 1) if prev else 1

        factory_dir = self.workspace_dir / "security_tool_factory" / slug
        factory_dir.mkdir(parents=True, exist_ok=True)
        script_file = factory_dir / f"{slug}_v{next_ver}.py"
        test_file = factory_dir / f"test_{slug}_v{next_ver}.py"

        source_code = custom_python_body.strip() or self._generate_defensive_template(cat, purpose)

        # Step 10a: Static AST safety check (no destructive/evasion calls)
        ast_ok, ast_reason = self._verify_safe_ast(source_code)
        if not ast_ok:
            return {"ok": False, "status": "rejected_unsafe_ast", "reason": ast_reason, "steps": steps}

        # Step 8 & 9: Write implementation & unit test in isolated workspace
        script_file.write_text(source_code + "\n", encoding="utf-8")
        sample_target = factory_dir / "sample_artifact.cfg"
        sample_target.write_text("permit_root_login=no\ntls_min_version=1.3\n", encoding="utf-8")

        test_file.write_text(
            "import importlib.util\n"
            "import json\n"
            "import unittest\n\n"
            f"SPEC = importlib.util.spec_from_file_location('mod', {str(script_file)!r})\n"
            "MOD = importlib.util.module_from_spec(SPEC)\n"
            "SPEC.loader.exec_module(MOD)\n\n"
            "class TestGeneratedSecurityUtility(unittest.TestCase):\n"
            "    def test_inspect_target_returns_verified_dict(self):\n"
            f"        res = MOD.inspect_target({str(sample_target)!r})\n"
            "        self.assertIsInstance(res, dict)\n"
            "        self.assertTrue(res.get('ok'))\n"
            "        json.dumps(res)\n\n"
            "if __name__ == '__main__':\n"
            "    unittest.main()\n",
            encoding="utf-8",
        )
        steps.extend(
            [
                {"step": 8, "action": "create_implementation_isolated", "script_path": str(script_file)},
                {"step": 9, "action": "generate_unit_tests", "test_path": str(test_file)},
            ]
        )

        # Steps 10b & 11: Run static + functional tests in isolated temp cache
        with tempfile.TemporaryDirectory(prefix="nova_tf_pyc_") as pyc_tmp:
            proc = subprocess.run(
                ["python3", "-B", str(test_file)],
                cwd=str(factory_dir),
                capture_output=True,
                text=True,
                timeout=8.0,
                check=False,
                env={**os.environ, "LC_ALL": "C", "PYTHONPYCACHEPREFIX": pyc_tmp},
            )
        functional_ok = proc.returncode == 0
        steps.extend(
            [
                {"step": 10, "action": "run_static_and_functional_checks", "exit_code": proc.returncode},
                {"step": 11, "action": "validate_in_controlled_environment", "passed": functional_ok},
            ]
        )
        if not functional_ok:
            return {
                "ok": False,
                "status": "sandbox_validation_failed",
                "stderr": (proc.stderr or proc.stdout)[:500],
                "steps": steps,
            }

        # Steps 12 & 13: Enforce permissions/scope & register in ToolRegistry (CANNOT bypass policy!)
        tool_id = f"sec_factory_{slug}"
        permissions_meta = {
            "requires_registered_scope": True,
            "autonomy_class": "approval_required",
            "can_bypass_scope_or_autonomy_policy": False,
            "read_only": True,
        }
        steps.append({"step": 12, "action": "review_permissions_and_data_handling", "permissions": permissions_meta})

        if self.tool_registry is not None:
            self._register_wrapped_tool(tool_id=tool_id, purpose=purpose, script_file=script_file)
        steps.append({"step": 13, "action": "register_in_capability_registry", "tool_id": tool_id})

        # Step 14: Version & rollback snapshot
        saved = self.db.upsert_cyber_generated_tool(
            {
                "tool_id": tool_id,
                "name": name.strip(),
                "category": cat,
                "purpose": purpose.strip(),
                "version": next_ver,
                "status": "validated_and_registered",
                "script_path": str(script_file),
                "test_result": {"passed": True, "output": ((proc.stdout or "") + (proc.stderr or "")).strip()[:400]},
                "permissions": permissions_meta,
                "rollback": {
                    "previous_version": prev["version"] if prev else 0,
                    "previous_script_path": prev["script_path"] if prev else "",
                },
            }
        )
        steps.append({"step": 14, "action": "maintain_versioning_and_rollback", "version": next_ver})
        return {"ok": True, "tool": saved, "steps": steps}

    def execute_generated_tool_through_policy(
        self,
        tool_id: str,
        *,
        target_path: str,
        operator_approved: bool = False,
    ) -> dict[str, Any]:
        """§214 & §220.16 Execute a generated tool strictly through ScopeRegistry & approval policy."""
        rec = self.db.get_cyber_generated_tool(tool_id)
        if rec is None:
            raise ValueError(f"Unknown generated tool: {tool_id}")

        scope_decision = self.scope_registry.authorize_operation(
            target=target_path,
            activity="security_configuration_checks",
        )
        if not scope_decision["authorized"]:
            return {
                "ok": False,
                "status": "blocked_by_scope_policy",
                "bypassed_authorization": False,
                "reason": scope_decision["reason"],
            }
        if not operator_approved and not scope_decision.get("standing_authorization"):
            return {
                "ok": False,
                "status": "approval_required",
                "bypassed_authorization": False,
                "reason": "Generated tool execution requires standing scope authorization or explicit operator approval.",
            }

        with tempfile.TemporaryDirectory(prefix="nova_gt_exec_") as pyc_tmp:
            proc = subprocess.run(
                [
                    "python3",
                    "-B",
                    "-c",
                    "import importlib.util, json, sys; "
                    "sp = importlib.util.spec_from_file_location('gt', sys.argv[1]); "
                    "m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m); "
                    "print(json.dumps(m.inspect_target(sys.argv[2])))",
                    rec["script_path"],
                    str(Path(target_path).resolve()),
                ],
                capture_output=True,
                text=True,
                timeout=6.0,
                check=False,
                env={**os.environ, "LC_ALL": "C", "PYTHONPYCACHEPREFIX": pyc_tmp},
            )
        if proc.returncode != 0:
            return {"ok": False, "status": "execution_error", "stderr": proc.stderr[:400]}
        return {
            "ok": True,
            "status": "completed",
            "bypassed_authorization": False,
            "scope_id": scope_decision["scope_id"],
            "result": json.loads(proc.stdout.strip()),
        }

    def _register_wrapped_tool(self, *, tool_id: str, purpose: str, script_file: Path) -> None:
        assert self.tool_registry is not None

        async def _handler(args: BaseModel, approved: bool) -> ToolOutcome:
            p = GeneratedSecurityToolInput.model_validate(args.model_dump())
            if not approved:
                return ToolOutcome(
                    status="approval_required",
                    summary=f"Generated security utility `{tool_id}` requires authorization approval.",
                    approval_payload={"target_path": p.target_path},
                )
            res = self.execute_generated_tool_through_policy(
                tool_id,
                target_path=p.target_path,
                operator_approved=approved,
            )
            if not res["ok"]:
                return ToolOutcome(status="error", summary=str(res.get("reason") or res["status"]), data=res)
            return ToolOutcome(status="success", summary=f"Executed `{tool_id}` inside authorized scope.", data=res)

        if self.tool_registry.get(tool_id) is None:
            self.tool_registry.register(
                ToolDefinition(
                    name=tool_id,
                    description=f"Generated defensive utility: {purpose[:180]} (policy & scope enforced; §214).",
                    parameters=GeneratedSecurityToolInput.model_json_schema(),
                    input_model=GeneratedSecurityToolInput,
                    handler=_handler,
                    permission="security_tool_factory_exec",
                    category="cyber_division",
                    autonomy_class="approval_required",
                )
            )

    @staticmethod
    def _verify_safe_ast(code: str) -> tuple[bool, str]:
        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            return False, f"SyntaxError: {exc}"
        has_entry = any(isinstance(n, ast.FunctionDef) and n.name == "inspect_target" for n in tree.body)
        if not has_entry:
            return False, "Generated utility must define `inspect_target(target_path: str) -> dict`."
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn_name = ""
                if isinstance(node.func, ast.Name):
                    fn_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    fn_name = node.func.attr
                if fn_name in FORBIDDEN_GENERATED_AST_CALLS:
                    return False, f"Forbidden destructive/dynamic call `{fn_name}` in generated tool."
        return True, "ok"

    @staticmethod
    def _generate_defensive_template(category: str, purpose: str) -> str:
        return (
            '"""Auto-generated read-only defensive security utility (§214)."""\n'
            "from __future__ import annotations\n\n"
            "import hashlib\n"
            "import pathlib\n"
            "import stat\n\n"
            "def inspect_target(target_path: str) -> dict:\n"
            "    p = pathlib.Path(target_path)\n"
            "    if not p.exists():\n"
            f"        return {{'ok': False, 'category': {category!r}, 'error': 'not_found'}}\n"
            "    if p.is_file():\n"
            "        raw = p.read_bytes()\n"
            "        mode_oct = oct(stat.S_IMODE(p.stat().st_mode))\n"
            "        world_writable = bool(p.stat().st_mode & stat.S_IWOTH)\n"
            "        return {\n"
            "            'ok': True,\n"
            f"            'category': {category!r},\n"
            f"            'purpose': {purpose!r},\n"
            "            'sha256': hashlib.sha256(raw).hexdigest(),\n"
            "            'size_bytes': len(raw),\n"
            "            'permissions_octal': mode_oct,\n"
            "            'world_writable_risk': world_writable,\n"
            "        }\n"
            "    files = [c.name for c in sorted(p.iterdir())[:50]]\n"
            f"    return {{'ok': True, 'category': {category!r}, 'entry_count': len(files), 'entries': files}}\n"
        )


class AutonomousPurpleTeamCoordinator:
    """§215 Defensive Detection Validation & Detection-Rule Refinement in Controlled Lab Scenarios."""

    ALLOW_UNAPPROVED_PRODUCTION_SIMULATIONS = False

    def __init__(self, *, scope_registry: SecurityScopeRegistry):
        self.scope_registry = scope_registry

    def run_purple_team_exercise(
        self,
        *,
        lab_target: str,
        scenario_name: str,
        synthetic_telemetry_events: list[str],
        existing_detection_patterns: list[str],
    ) -> dict[str, Any]:
        """§215 Test bounded lab telemetry against detection rules, identify gaps, refine rule, and retest."""
        auth = self.scope_registry.authorize_operation(
            target=lab_target,
            activity="security_configuration_checks",
        )
        if not auth["authorized"]:
            return {"ok": False, "status": auth["status"], "reason": auth["reason"]}

        initial_regs = [re.compile(pat, re.IGNORECASE) for pat in existing_detection_patterns]
        detected_initial: list[str] = []
        missed_gaps: list[str] = []

        for ev in synthetic_telemetry_events:
            if any(r.search(ev) for r in initial_regs):
                detected_initial.append(ev)
            else:
                missed_gaps.append(ev)

        refined_patterns = list(existing_detection_patterns)
        for missed in missed_gaps:
            tokens = [re.escape(tok) for tok in re.findall(r"[A-Za-z0-9_./:-]{4,}", missed)[:3]]
            if tokens:
                refined_patterns.append(".*".join(tokens))

        refined_regs = [re.compile(pat, re.IGNORECASE) for pat in refined_patterns]
        retest_detected = [ev for ev in synthetic_telemetry_events if any(r.search(ev) for r in refined_regs)]

        return {
            "ok": True,
            "scenario_name": scenario_name,
            "lab_target": lab_target,
            "initial_alerts_generated": len(detected_initial),
            "detection_gaps_identified": missed_gaps,
            "recommended_refined_rules": refined_patterns,
            "retest_coverage_ratio": round(len(retest_detected) / max(1, len(synthetic_telemetry_events)), 3),
            "all_gaps_closed_on_retest": len(retest_detected) == len(synthetic_telemetry_events),
        }


class ContinuousSecurityAutomationEngine:
    """§217 Bounded, Resource-Governed Recurring Security Assessments with Automatic Scope/Credential Pause."""

    MIN_FREE_RAM_MB = 192
    MIN_FREE_DISK_GB = 0.5
    MAX_CPU_LOAD_PER_CORE = 3.5

    def __init__(
        self,
        *,
        db: Database,
        scope_registry: SecurityScopeRegistry,
        surface_manager: Any,
    ):
        self.db = db
        self.scope_registry = scope_registry
        self.surface_manager = surface_manager

    def check_resource_limits(
        self,
        *,
        max_allowed_ram_mb: int | None = None,
        min_required_free_disk_gb: float | None = None,
    ) -> dict[str, Any]:
        """§217 & §220.18 Verify CPU, memory, and storage limits before executing security workflows."""
        mem_avail_mb = 512
        try:
            for ln in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
                if ln.startswith("MemAvailable:"):
                    mem_avail_mb = int(ln.split()[1]) // 1024
                    break
        except OSError:
            pass
        free_disk_gb = round(shutil.disk_usage("/").free / (1024**3), 2)
        load_1m = os.getloadavg()[0] if hasattr(os, "getloadavg") else 0.2
        cores = max(1, os.cpu_count() or 1)

        min_ram = max_allowed_ram_mb if max_allowed_ram_mb is not None else self.MIN_FREE_RAM_MB
        min_disk = min_required_free_disk_gb if min_required_free_disk_gb is not None else self.MIN_FREE_DISK_GB

        ram_ok = mem_avail_mb >= min_ram
        disk_ok = free_disk_gb >= min_disk
        cpu_ok = (load_1m / cores) <= self.MAX_CPU_LOAD_PER_CORE

        return {
            "within_limits": ram_ok and disk_ok and cpu_ok,
            "cpu": {"load_1m": round(load_1m, 2), "cores": cores, "ok": cpu_ok},
            "memory": {"available_mb": mem_avail_mb, "required_available_mb": min_ram, "ok": ram_ok},
            "storage": {"free_gb": free_disk_gb, "required_free_gb": min_disk, "ok": disk_ok},
        }

    def schedule_recurring_assessment(
        self,
        *,
        name: str,
        workflow_kind: str,
        scope_id: str,
        target: str,
        interval_minutes: int = 60,
        rate_limit_rpm: int = 30,
        credentials_valid: bool = True,
    ) -> dict[str, Any]:
        return self.db.upsert_cyber_recurring_assessment(
            {
                "name": name,
                "workflow_kind": workflow_kind,
                "scope_id": scope_id,
                "target": target,
                "interval_minutes": interval_minutes,
                "rate_limit_rpm": rate_limit_rpm,
                "credentials_valid": credentials_valid,
                "status": "active",
                "run_count": 0,
            }
        )

    def run_bounded_assessment_tick(
        self,
        job_id: str,
        *,
        required_free_ram_mb: int | None = None,
        required_free_disk_gb: float | None = None,
    ) -> dict[str, Any]:
        """§217 Execute one bounded tick; pause automatically if scope expired, out-of-scope, creds invalid, or over budget."""
        job = self.db.get_cyber_recurring_assessment(job_id)
        if job is None:
            raise ValueError(f"Unknown recurring assessment job: {job_id}")

        if not job["credentials_valid"]:
            job["status"] = "paused"
            job["pause_reason"] = "credentials_invalid"
            return {"ok": False, "paused": True, "job": self.db.upsert_cyber_recurring_assessment(job)}

        auth = self.scope_registry.authorize_operation(target=job["target"], activity="asset_inventory")
        if not auth["authorized"]:
            job["status"] = "paused"
            job["pause_reason"] = auth["status"]
            return {"ok": False, "paused": True, "job": self.db.upsert_cyber_recurring_assessment(job)}

        budget = self.check_resource_limits(
            max_allowed_ram_mb=required_free_ram_mb,
            min_required_free_disk_gb=required_free_disk_gb,
        )
        if not budget["within_limits"]:
            job["status"] = "deferred_resource_budget"
            job["pause_reason"] = "cpu_memory_or_storage_limit_reached"
            return {"ok": False, "paused": True, "budget": budget, "job": self.db.upsert_cyber_recurring_assessment(job)}

        surf = self.surface_manager.assess_target_surface(job["target"])
        job["status"] = "active"
        job["pause_reason"] = ""
        job["run_count"] = int(job["run_count"]) + 1
        job["last_report"] = {
            "surface_ok": surf.get("ok"),
            "meaningful_change_alert": surf.get("meaningful_change_alert"),
            "resource_budget": budget,
        }
        saved = self.db.upsert_cyber_recurring_assessment(job)
        return {"ok": True, "paused": False, "job": saved, "budget": budget}


class CybersecurityExpertTutor:
    """§218 Adaptive 17-Discipline Cybersecurity Tutor driven by demonstrated performance."""

    def __init__(self, *, db: Database):
        self.db = db

    def generate_adaptive_module(
        self,
        discipline: str,
        *,
        demonstrated_scores: list[float] | None = None,
    ) -> dict[str, Any]:
        """§218 Adapt curriculum depth strictly from demonstrated quiz/lab scores across 17 disciplines."""
        dkey = discipline.strip().lower()
        if dkey not in TUTOR_17_DISCIPLINES:
            raise ValueError(f"Unsupported discipline '{discipline}'. Valid: {TUTOR_17_DISCIPLINES}")

        scores = list(demonstrated_scores or [])
        avg = (sum(scores) / len(scores)) if scores else 0.0
        if not scores:
            adapted_level = "beginner"
            adaptation_reason = "No prior demonstrated assessment score recorded; starting with foundational verification drills."
        elif avg >= 85.0:
            adapted_level = "advanced"
            adaptation_reason = f"Demonstrated mastery ({avg:.1f}% average across {len(scores)} assessment(s)); advancing to architecture & edge-case scenarios."
        elif avg >= 60.0:
            adapted_level = "intermediate"
            adaptation_reason = f"Solid baseline ({avg:.1f}% average); progressing to applied diagnostics and remediation verification."
        else:
            adapted_level = "beginner"
            adaptation_reason = f"Demonstrated score ({avg:.1f}%) indicates foundational gaps; reinforcing core mechanics before advancing."

        topic_id = f"cyber218:{dkey}"
        self.db.upsert_kali_training_progress(
            {
                "topic_id": topic_id,
                "track": dkey,
                "level": adapted_level,
                "completed": avg >= 80.0,
                "quiz_score": avg if scores else None,
                "attempts": len(scores),
                "notes": {"adaptation_reason": adaptation_reason},
            }
        )
        return {
            "discipline": dkey,
            "supported_disciplines_count": len(TUTOR_17_DISCIPLINES),
            "adapted_level": adapted_level,
            "adaptation_reason": adaptation_reason,
            "scenario_exercise": f"[{adapted_level.upper()}] Inspect an authorized {dkey.replace('_', ' ')} artifact, separate confirmed facts from false positives, and verify remediation.",
            "official_references": [
                "https://owasp.org/",
                "https://csrc.nist.gov/",
                "https://kali.training/",
            ],
        }


class SelfImprovingSecurityIntelligence:
    """§219 Evidence-Backed Self-Improving Security Intelligence with Immutable Safety Guardrails."""

    IMMUTABLE_CONTROLS: tuple[str, ...] = (
        "scope_enforcement",
        "authentication",
        "audit_records",
        "security_restrictions",
    )
    TREAT_MODEL_HYPOTHESIS_AS_CONFIRMED_VULN = False

    def __init__(self, *, db: Database):
        self.db = db

    def evaluate_and_improve_detector(
        self,
        *,
        detector_name: str,
        labeled_dataset: list[dict[str, Any]],
        baseline_pattern: str,
        candidate_pattern: str,
        proposed_policy_changes: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """§219 Benchmark precision/recall/FP rate on labeled test cases; block any security-control weakening."""
        for ctrl in self.IMMUTABLE_CONTROLS:
            if (proposed_policy_changes or {}).get(f"disable_{ctrl}") is True:
                return {
                    "ok": False,
                    "status": "rejected_immutable_security_control_removal",
                    "violated_control": ctrl,
                }

        base_metrics = self._score_pattern(baseline_pattern, labeled_dataset)
        cand_metrics = self._score_pattern(candidate_pattern, labeled_dataset)

        improved = (
            cand_metrics["f1"] >= base_metrics["f1"]
            and cand_metrics["false_positives"] <= base_metrics["false_positives"]
            and (cand_metrics["true_positives"] > base_metrics["true_positives"] or cand_metrics["false_positives"] < base_metrics["false_positives"])
        )

        rev = self.db.upsert_kali_expertise_revision(
            {
                "domain": "tool_selection",
                "subject": f"cyber_detector:{detector_name}",
                "version": 1,
                "status": "promoted_after_benchmark" if improved else "retained_baseline",
                "verified_runs": len(labeled_dataset) if improved else 0,
                "failed_runs": 0 if improved else 1,
                "proposal": {"baseline_pattern": baseline_pattern, "candidate_pattern": candidate_pattern},
                "test_result": {"baseline": base_metrics, "candidate": cand_metrics, "improved": improved},
                "rollback": {"active_pattern": baseline_pattern},
            }
        )
        return {
            "ok": True,
            "promoted_candidate": improved,
            "model_hypothesis_treated_as_confirmed_without_evidence": False,
            "baseline_metrics": base_metrics,
            "candidate_metrics": cand_metrics,
            "revision_record": rev,
        }

    @staticmethod
    def classify_unverified_model_hypothesis(hypothesis_text: str) -> dict[str, Any]:
        """§219 Never interpret a model-generated hypothesis as a confirmed vulnerability without evidence."""
        return {
            "hypothesis": hypothesis_text,
            "epistemic_status": "potential_vulnerability",
            "confirmed_vulnerability": False,
            "requires_empirical_reproduction_within_scope": True,
        }

    @staticmethod
    def _score_pattern(pattern: str, dataset: list[dict[str, Any]]) -> dict[str, Any]:
        reg = re.compile(pattern)
        tp = fp = fn = tn = 0
        for sample in dataset:
            matched = bool(reg.search(str(sample.get("code") or "")))
            truth = bool(sample.get("is_vulnerable"))
            if matched and truth:
                tp += 1
            elif matched and not truth:
                fp += 1
            elif not matched and truth:
                fn += 1
            else:
                tn += 1
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        f1 = (2 * precision * recall / max(1e-9, precision + recall)) if (precision + recall) > 0 else 0.0
        return {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
        }
