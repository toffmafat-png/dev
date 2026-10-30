"""§195 Universal Software Development Environment & §199 Self-Improving Kali Expertise."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from nova.db import Database
from nova.kali_intel.system_model import _run_probe

SUPPORTED_DEV_LANGUAGES: dict[str, dict[str, Any]] = {
    "python": {"extensions": [".py"], "manifests": ["pyproject.toml", "requirements.txt", "setup.py"], "toolchains": ["python3", "pytest", "ruff"]},
    "javascript": {"extensions": [".js", ".mjs", ".cjs"], "manifests": ["package.json"], "toolchains": ["node", "npm"]},
    "typescript": {"extensions": [".ts", ".tsx"], "manifests": ["tsconfig.json", "package.json"], "toolchains": ["tsc", "node", "npm"]},
    "c": {"extensions": [".c", ".h"], "manifests": ["Makefile", "CMakeLists.txt"], "toolchains": ["gcc", "clang", "make", "gdb"]},
    "cpp": {"extensions": [".cpp", ".cc", ".hpp"], "manifests": ["CMakeLists.txt", "Makefile"], "toolchains": ["g++", "clang++", "cmake", "gdb"]},
    "rust": {"extensions": [".rs"], "manifests": ["Cargo.toml"], "toolchains": ["rustc", "cargo"]},
    "go": {"extensions": [".go"], "manifests": ["go.mod"], "toolchains": ["go"]},
    "java": {"extensions": [".java"], "manifests": ["pom.xml", "build.gradle"], "toolchains": ["javac", "java", "mvn", "gradle"]},
    "shell": {"extensions": [".sh", ".bash"], "manifests": [], "toolchains": ["bash", "sh"]},
    "sql": {"extensions": [".sql"], "manifests": [], "toolchains": ["sqlite3", "psql"]},
    "html_css": {"extensions": [".html", ".css"], "manifests": [], "toolchains": ["python3", "node"]},
}

TOOLCHAIN_CATEGORIES: dict[str, tuple[str, ...]] = {
    "editors_and_ides": ("code", "nvim", "vim", "nano"),
    "compilers": ("gcc", "g++", "clang", "rustc", "javac"),
    "interpreters": ("python3", "node", "bash", "sh"),
    "debuggers": ("gdb", "lldb", "strace"),
    "build_tools": ("make", "cmake", "cargo", "npm", "go"),
    "version_control": ("git",),
    "database_tools": ("sqlite3", "psql", "mysql"),
    "testing_frameworks": ("pytest", "python3", "node", "cargo", "go"),
    "documentation_generators": ("pydoc3", "rustdoc", "javadoc", "pandoc"),
    "container_tools": ("docker", "podman"),
}

SELF_IMPROVEMENT_10_DOMAINS: tuple[str, ...] = (
    "tool_selection",
    "command_construction",
    "documentation_retrieval",
    "version_detection",
    "application_integration",
    "package_resolution",
    "hardware_diagnostics",
    "task_planning",
    "resource_management",
    "troubleshooting_procedures",
)

PRIVILEGE_OR_SECURITY_MUTATION_TOKENS: tuple[str, ...] = (
    "chmod u+s",
    "chmod 4755",
    "visudo",
    "nopasswd",
    "setenforce 0",
    "aa-disable",
    "ufw disable",
    "--no-sandbox",
)


class UniversalDevEnvironmentPartner:
    """§195 Multi-language software engineering inspection, toolchain discovery, and non-destructive test verification."""

    PRESERVE_PROJECT_STRUCTURE = True

    def __init__(self, *, workspace_dir: Path):
        self.workspace_dir = workspace_dir

    def inspect_installed_toolchains(self) -> dict[str, Any]:
        """§195 Discover installed editors, compilers, interpreters, debuggers, build/VCS/DB/test/doc/container tools."""
        discovered: dict[str, list[dict[str, str]]] = {}
        for category, cmds in TOOLCHAIN_CATEGORIES.items():
            items: list[dict[str, str]] = []
            for cmd in cmds:
                exe = shutil.which(cmd)
                if exe:
                    rc, out, err = _run_probe([exe, "--version"], timeout=2.0)
                    ver = ((out or err).splitlines() or [""])[0][:120] if rc == 0 else "installed"
                    items.append({"command": cmd, "executable_path": exe, "version": ver})
            discovered[category] = items
        return {
            "supported_languages": sorted(SUPPORTED_DEV_LANGUAGES.keys()),
            "toolchain_categories": discovered,
        }

    def analyze_and_verify_project(self, project_dir: Path | str, *, run_safe_checks: bool = True) -> dict[str, Any]:
        """§195 Analyze existing project structure & dependencies without clobbering files, running safe verification."""
        root = Path(project_dir).resolve()
        if not root.is_dir():
            raise ValueError(f"Project directory does not exist: {root}")

        ext_counts: dict[str, int] = {}
        manifests_found: list[str] = []
        top_entries = sorted(p.name for p in root.iterdir())[:50]

        for _dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in {".git", ".venv", "node_modules", "__pycache__", "target", "dist"}]
            for fname in filenames:
                ext = Path(fname).suffix.lower()
                if ext:
                    ext_counts[ext] = ext_counts.get(ext, 0) + 1
                for lang_meta in SUPPORTED_DEV_LANGUAGES.values():
                    if fname in lang_meta["manifests"] and fname not in manifests_found:
                        manifests_found.append(fname)

        detected_languages: list[str] = []
        for lang, meta in SUPPORTED_DEV_LANGUAGES.items():
            if any(ext_counts.get(ext, 0) > 0 for ext in meta["extensions"]) or any(m in manifests_found for m in meta["manifests"]):
                detected_languages.append(lang)

        verification_runs: list[dict[str, Any]] = []
        if run_safe_checks:
            if "python" in detected_languages and shutil.which("python3"):
                py_files = [str(p) for p in root.rglob("*.py") if ".venv" not in p.parts][:20]
                if py_files:
                    with tempfile.TemporaryDirectory(prefix="nova_pycheck_") as pyc_tmp:
                        try:
                            proc = subprocess.run(
                                ["python3", "-B", "-m", "py_compile", *py_files],
                                capture_output=True,
                                text=True,
                                timeout=8.0,
                                check=False,
                                env={**os.environ, "LC_ALL": "C", "PYTHONPYCACHEPREFIX": pyc_tmp},
                            )
                            rc, err = proc.returncode, (proc.stderr or "").strip()
                        except (OSError, subprocess.SubprocessError) as exc:
                            rc, err = 1, str(exc)
                    verification_runs.append(
                        {"check": "python_syntax_compile", "ok": rc == 0, "files_checked": len(py_files), "stderr": err[:300]}
                    )
            if "shell" in detected_languages and shutil.which("sh"):
                sh_files = [str(p) for p in root.rglob("*.sh") if ".venv" not in p.parts][:10]
                for sf in sh_files:
                    rc, _, err = _run_probe(["sh", "-n", sf], timeout=3.0)
                    verification_runs.append({"check": f"posix_shell_syntax:{Path(sf).name}", "ok": rc == 0, "stderr": err[:200]})

        after_entries = sorted(p.name for p in root.iterdir())[:50]
        return {
            "project_root": str(root),
            "preserved_existing_structure": top_entries == after_entries,
            "detected_languages": sorted(detected_languages),
            "manifests_found": sorted(manifests_found),
            "extension_histogram": ext_counts,
            "verification_runs": verification_runs,
        }


class SelfImprovingKaliExpertise:
    """§199 Controlled 8-step Self-Improving Kali Expertise with versioned procedures, rollback & privilege guards."""

    ALLOW_SECURITY_OR_PRIVILEGE_ESCALATION = False
    MIN_VERIFIED_RUNS_FOR_ESTABLISHED_RULE = 3

    def __init__(self, *, db: Database):
        self.db = db

    def propose_and_test_improvement(
        self,
        *,
        domain: str,
        subject: str,
        baseline_argv: list[str],
        improved_argv: list[str],
        hypothesis: str,
    ) -> dict[str, Any]:
        """§199 Execute the 8-step isolated improvement verification loop without privilege or security mutation."""
        dom = domain.strip().lower()
        if dom not in SELF_IMPROVEMENT_10_DOMAINS:
            raise ValueError(f"Unsupported improvement domain '{domain}'. Valid: {SELF_IMPROVEMENT_10_DOMAINS}")

        joined = " ".join(improved_argv).lower()
        if any(tok in joined for tok in PRIVILEGE_OR_SECURITY_MUTATION_TOKENS):
            return {
                "ok": False,
                "status": "rejected_security_or_privilege_mutation",
                "reason": "Self-improvement may never alter security controls or grant greater privileges.",
            }

        existing = [
            r for r in self.db.list_kali_expertise_revisions(domain=dom, limit=100) if r["subject"].lower() == subject.strip().lower()
        ]
        prev_record = existing[0] if existing else None
        next_version = (int(prev_record["version"]) + 1) if prev_record else 1

        # Step 4 & 5: Test both baseline and candidate inside isolated temp sandbox & compare!
        base_res = self._run_isolated(baseline_argv) if baseline_argv else {"ok": False, "exit_code": 1, "duration_ms": 0}
        cand_res = self._run_isolated(improved_argv)

        outperformed_or_verified = bool(cand_res["ok"]) and (not base_res["ok"] or cand_res["duration_ms"] <= base_res["duration_ms"] + 2000)
        verified_runs = (int(prev_record["verified_runs"]) if prev_record else 0) + (1 if outperformed_or_verified else 0)
        failed_runs = (int(prev_record["failed_runs"]) if prev_record else 0) + (0 if outperformed_or_verified else 1)

        # §199 Never turn ONE successful command into a universally valid rule!
        if not outperformed_or_verified:
            status = "rejected_failed_verification"
        elif verified_runs >= self.MIN_VERIFIED_RUNS_FOR_ESTABLISHED_RULE:
            status = "established_verified_rule"
        else:
            status = "candidate_pending_additional_runs"

        saved = self.db.upsert_kali_expertise_revision(
            {
                "id": prev_record["id"] if prev_record else None,
                "domain": dom,
                "subject": subject.strip(),
                "version": next_version,
                "status": status,
                "verified_runs": verified_runs,
                "failed_runs": failed_runs,
                "proposal": {
                    "hypothesis": hypothesis,
                    "improved_argv": improved_argv,
                    "baseline_argv": baseline_argv,
                },
                "test_result": {
                    "candidate": cand_res,
                    "baseline": base_res,
                    "outperformed_or_verified": outperformed_or_verified,
                },
                "rollback": {
                    "previous_version": prev_record["version"] if prev_record else 0,
                    "previous_argv": prev_record["proposal"].get("improved_argv", baseline_argv) if prev_record else baseline_argv,
                },
            }
        )
        return {
            "ok": outperformed_or_verified,
            "single_run_treated_as_universal_rule": False,
            "security_controls_altered": False,
            "revision": saved,
        }

    def rollback_revision(self, revision_id: str) -> dict[str, Any]:
        rec = self.db.get_kali_expertise_revision(revision_id)
        if rec is None:
            raise ValueError(f"Unknown revision_id: {revision_id}")
        rb = rec["rollback"]
        restored_argv = rb.get("previous_argv") or rec["proposal"].get("baseline_argv") or []
        updated = self.db.upsert_kali_expertise_revision(
            {
                "id": rec["id"],
                "domain": rec["domain"],
                "subject": rec["subject"],
                "version": int(rec["version"]) + 1,
                "status": "rolled_back",
                "verified_runs": 0,
                "failed_runs": rec["failed_runs"],
                "proposal": {**rec["proposal"], "active_argv": restored_argv},
                "test_result": rec["test_result"],
                "rollback": rb,
            }
        )
        return {"ok": True, "rolled_back_to_argv": restored_argv, "revision": updated}

    @staticmethod
    def _run_isolated(argv: list[str]) -> dict[str, Any]:
        import time

        if not argv:
            return {"ok": False, "exit_code": 127, "duration_ms": 0, "output": "empty argv"}
        exe = shutil.which(argv[0]) or (argv[0] if Path(argv[0]).is_file() else "")
        if not exe:
            return {"ok": False, "exit_code": 127, "duration_ms": 0, "output": f"{argv[0]} not installed"}
        t0 = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="nova_exp_test_") as tmp_dir:
            try:
                proc = subprocess.run(
                    [exe, *argv[1:]],
                    cwd=tmp_dir,
                    capture_output=True,
                    text=True,
                    timeout=5.0,
                    check=False,
                    env={**os.environ, "LC_ALL": "C"},
                )
                dt = round((time.monotonic() - t0) * 1000.0, 2)
                return {
                    "ok": proc.returncode == 0,
                    "exit_code": proc.returncode,
                    "duration_ms": dt,
                    "output": ((proc.stdout or proc.stderr or "").strip())[:300],
                }
            except (OSError, subprocess.SubprocessError) as exc:
                dt = round((time.monotonic() - t0) * 1000.0, 2)
                return {"ok": False, "exit_code": 1, "duration_ms": dt, "output": str(exc)[:300]}
