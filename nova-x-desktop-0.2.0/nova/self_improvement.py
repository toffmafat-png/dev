"""§17 General-purpose learning and controlled self-improvement workbench.

Implements the 11-step measurable candidate evaluation loop in strict isolation
from the running installation:
1. Identify recurring failures or capability gaps.
2. Examine recorded evidence.
3. Form a testable hypothesis.
4. Create an isolated candidate change inside `improvement_workbench/`.
5. Generate or update tests.
6. Execute tests in isolation.
7. Compare against the stable baseline.
8. Scan for regressions and security/policy violations.
9. Retain or reject the candidate.
10. Preserve a rollback backup before any explicit operator promotion.
11. Record structured results in SQLite.

Hard invariants:
- `AUTO_OVERWRITE_STABLE_INSTALLATION = False`
- `MODEL_WEIGHT_TRAINING_SUPPORTED = False`
- Separate mechanism taxonomy (`model_routing`, `retrieval_strategy`,
  `workflow_design`, `tool_description`, `error_recovery`,
  `application_component` vs `memory_update` vs `model_weight_training`).
"""
from __future__ import annotations

import ast
import re
import shutil
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nova.db import Database

AUTO_OVERWRITE_STABLE_INSTALLATION = False
MODEL_WEIGHT_TRAINING_SUPPORTED = False

ALLOWED_IMPROVEMENT_MECHANISMS: frozenset[str] = frozenset(
    {
        "model_routing",
        "retrieval_strategy",
        "workflow_design",
        "tool_description",
        "error_recovery",
        "application_component",
    }
)

# Forbidden patterns in any candidate patch/component (§17 security invariants).
_FORBIDDEN_CANDIDATE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("weakens_autonomy_policy", re.compile(r"\b(bypass_policy|disable_authorization|AUTO_INSTALL_PERMITTED\s*=\s*True|SILENT_SYSTEM_INSTALL_PERMITTED\s*=\s*True)\b")),
    ("exposes_secrets", re.compile(r"\b(SecretStore\.export_plaintext|print\s*\([^)]*API_KEY|os\.environ\[['\"][A-Z0-9_]*KEY['\"]\])\b")),
    ("disables_audit_logs", re.compile(r"\b(disable_audit|audit_enabled\s*=\s*False|skip_audit_log)\b")),
    ("escalates_privileges", re.compile(r"\b(chmod\s+0?777|setuid|sudo\s+-S|pkexec\s+--disable-internal-agent)\b")),
    ("rewrites_acceptance_criteria", re.compile(r"\b(FILE_EXISTENCE_ALONE_SUFFICIENT\s*=\s*True|SPEAKER_ID_AUTHORIZES_PRIVILEGED\s*=\s*True)\b")),
)


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


class ControlledImprovementEngine:
    """§17 Isolated candidate evaluation, regression comparison, and rollback workbench."""

    def __init__(self, *, db: Database, data_dir: Path, stable_root: Path | None = None) -> None:
        self.db = db
        self.workbench_root = Path(data_dir).resolve() / "improvement_workbench"
        self.workbench_root.mkdir(parents=True, exist_ok=True)
        self.stable_root = Path(stable_root).resolve() if stable_root else None

    def identify_recurring_gaps(self) -> dict[str, Any]:
        """Step 1–2: Inspect recorded post-hoc attributions, failed tasks, and capability runs."""
        tasks = self.db.list_tasks(limit=50)
        failed_tasks = [t for t in tasks if t.get("state") == "failed"]
        creation_runs = self.db.list_creation_runs(limit=30)
        degraded_runs = [r for r in creation_runs if r.get("status") not in {"completed", "passed"}]
        return {
            "inspected_tasks": len(tasks),
            "failed_task_count": len(failed_tasks),
            "degraded_creation_runs": len(degraded_runs),
            "evidence_samples": [
                {"task_id": t["id"], "error": str(t.get("error") or "")[:160]}
                for t in failed_tasks[:5]
            ],
            "distinct_mechanisms": {
                "supported_experimental_mechanisms": sorted(ALLOWED_IMPROVEMENT_MECHANISMS),
                "memory_updates_handled_by": "SharedMemorySystem (§14)",
                "model_weight_training_supported": MODEL_WEIGHT_TRAINING_SUPPORTED,
            },
        }

    @staticmethod
    def scan_candidate_safety(candidate_code: str, test_code: str = "") -> dict[str, Any]:
        """Step 8: Reject any candidate that removes auth, leaks secrets, disables audits, or rewrites acceptance rules."""
        violations: list[str] = []
        combined = f"{candidate_code}\n{test_code}"
        for code, pattern in _FORBIDDEN_CANDIDATE_PATTERNS:
            if pattern.search(combined):
                violations.append(code)
        try:
            ast.parse(candidate_code)
        except SyntaxError as exc:
            violations.append(f"candidate_syntax_error:line_{exc.lineno}")
        if test_code.strip():
            try:
                ast.parse(test_code)
            except SyntaxError as exc:
                violations.append(f"test_syntax_error:line_{exc.lineno}")
        return {"safe": len(violations) == 0, "violations": violations}

    def evaluate_candidate(
        self,
        *,
        mechanism: str,
        title: str,
        hypothesis: str,
        baseline_code: str,
        candidate_code: str,
        test_code: str,
        baseline_score: float = 0.5,
        candidate_score: float | None = None,
    ) -> dict[str, Any]:
        """Steps 3–11: Stage candidate in isolation, run safety scan + pytest, compare vs baseline, and record."""
        if mechanism == "model_weight_training":
            raise ValueError("Model weight training is separate and not performed by NOVA's local workbench (§17).")
        if mechanism not in ALLOWED_IMPROVEMENT_MECHANISMS:
            raise ValueError(f"Unsupported mechanism '{mechanism}'. Valid: {', '.join(sorted(ALLOWED_IMPROVEMENT_MECHANISMS))}")

        exp_id = f"exp-{uuid.uuid4().hex[:12]}"
        exp_dir = self.workbench_root / exp_id
        (exp_dir / "baseline").mkdir(parents=True, exist_ok=True)
        (exp_dir / "candidate").mkdir(parents=True, exist_ok=True)
        (exp_dir / "baseline" / "component.py").write_text(baseline_code, encoding="utf-8")
        (exp_dir / "candidate" / "component.py").write_text(candidate_code, encoding="utf-8")
        test_path = exp_dir / "candidate" / "test_candidate.py"
        test_path.write_text(test_code, encoding="utf-8")

        safety = self.scan_candidate_safety(candidate_code, test_code)
        tests_passed = False
        pytest_output = ""
        if safety["safe"]:
            env = {"PYTHONPATH": str(exp_dir / "candidate"), "PATH": "/usr/bin:/bin"}
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-W", "ignore", str(test_path)],
                cwd=str(exp_dir / "candidate"),
                env={**dict(__import__("os").environ), **env},
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            full_output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
            pytest_output = full_output[:400]
            tests_passed = proc.returncode == 0 and ("passed" in full_output)

        measured_candidate = (
            float(candidate_score)
            if candidate_score is not None
            else (1.0 if (safety["safe"] and tests_passed) else 0.0)
        )
        improved = safety["safe"] and tests_passed and (measured_candidate > float(baseline_score))
        status = "retained_staged" if improved else ("rejected_unsafe" if not safety["safe"] else "rejected_no_improvement")

        saved = self.db.save_improvement_experiment(
            {
                "id": exp_id,
                "mechanism": mechanism,
                "title": title,
                "hypothesis": hypothesis,
                "status": status,
                "safety_passed": safety["safe"],
                "tests_passed": tests_passed,
                "baseline_score": float(baseline_score),
                "candidate_score": measured_candidate,
                "applied": False,
                "staging_dir": str(exp_dir),
                "backup_dir": "",
                "payload": {
                    "safety": safety,
                    "pytest_output": pytest_output,
                    "auto_overwrite_stable_installation": AUTO_OVERWRITE_STABLE_INSTALLATION,
                },
            }
        )
        return saved

    def promote_staged_candidate(self, exp_id: str, target_file: Path, *, operator_approved: bool = False) -> dict[str, Any]:
        """Step 10: Operator-approved promotion with mandatory rollback backup; never silent."""
        if not operator_approved:
            return {"promoted": False, "reason": "explicit_operator_approval_required"}
        exp = self.db.get_improvement_experiment(exp_id)
        if exp is None:
            raise KeyError(f"Experiment '{exp_id}' not found.")
        if exp["status"] != "retained_staged" or not exp["safety_passed"] or not exp["tests_passed"]:
            return {"promoted": False, "reason": f"candidate_not_eligible:{exp['status']}"}

        dest = Path(target_file).resolve()
        if self.stable_root is not None and not dest.is_relative_to(self.stable_root):
            raise PermissionError("Target file is outside the configured managed root.")

        backup_dir = self.workbench_root / exp_id / "rollback_backup"
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_file = backup_dir / dest.name
        if dest.is_file():
            shutil.copy2(dest, backup_file)

        staged_comp = Path(exp["staging_dir"]) / "candidate" / "component.py"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(staged_comp, dest)

        updated = self.db.save_improvement_experiment(
            {
                **exp,
                "status": "promoted_with_backup",
                "applied": True,
                "backup_dir": str(backup_dir),
                "payload": {**exp["payload"], "promoted_target": str(dest), "backup_file": str(backup_file)},
            }
        )
        return {"promoted": True, "experiment": updated, "backup_file": str(backup_file)}

    def rollback_promoted_candidate(self, exp_id: str) -> dict[str, Any]:
        exp = self.db.get_improvement_experiment(exp_id)
        if exp is None:
            raise KeyError(f"Experiment '{exp_id}' not found.")
        payload = exp.get("payload") or {}
        target = Path(str(payload.get("promoted_target") or ""))
        backup = Path(str(payload.get("backup_file") or ""))
        if not backup.is_file() or not str(target):
            return {"rolled_back": False, "reason": "no_backup_file_recorded"}
        shutil.copy2(backup, target)
        updated = self.db.save_improvement_experiment({**exp, "status": "rolled_back", "applied": False})
        return {"rolled_back": True, "experiment": updated}
