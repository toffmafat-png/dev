"""§100 Advanced developer environment.

Provides real software-engineering inspection and isolated candidate-patch
verification over a local repository without requiring Docker or Podman:

* Read-only git status, branch and diff inspection.
* Explicit approval gate for destructive git operations, protected-branch
  mutations, production deployments and external package publication.
* Repository search and symbol navigation.
* Dependency manifest & security/pinning inspection across Python and Node.js,
  preferring project-local virtualenvs/node_modules over system-wide installs.
* Test discovery, Ruff diagnostic parsing, Python traceback root-cause analysis,
  deployment-config inspection, and sandboxed candidate-patch evaluation that
  leaves the working tree untouched.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from nova.knowledge import DEFAULT_EXCLUDED_DIRS, extract_symbols, is_excluded
from nova.sandbox import RISK_GENERATED_CODE, STATUS_COMPLETED, Sandbox, SandboxPolicy

PROTECTED_BRANCHES = frozenset({"main", "master", "production", "release"})

_DESTRUCTIVE_GIT_PATTERNS = re.compile(
    r"\b(reset\s+--hard|clean\s+-[a-z]*f|push\s+.*--force|push\s+-f|branch\s+-D|checkout\s+--\s+\.)\b"
)
_PUBLISH_OR_DEPLOY_PATTERNS = re.compile(
    r"\b(twine\s+upload|npm\s+publish|cargo\s+publish|kubectl\s+apply|helm\s+upgrade|terraform\s+apply|gh\s+release\s+create)\b"
)
_TRACEBACK_FRAME_RE = re.compile(r'^\s*File "([^"]+)", line (\d+), in (\S+)')


def _run_git(repo_root: Path, args: list[str], *, timeout: float = 10.0) -> tuple[int, str, str]:
    git_bin = shutil.which("git")
    if not git_bin:
        return 127, "", "git binary is not installed"
    proc = subprocess.run(
        [git_bin, *args],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def check_git_or_deploy_action(
    command: str,
    *,
    target_branch: str = "",
    is_production: bool = False,
    operator_approved: bool = False,
) -> dict[str, Any]:
    """Enforce §100 permission rules on destructive git, protected branches, deploy & publish."""
    reasons: list[str] = []
    if _DESTRUCTIVE_GIT_PATTERNS.search(command or ""):
        reasons.append("destructive git command detected")
    if _PUBLISH_OR_DEPLOY_PATTERNS.search(command or "") or is_production:
        reasons.append("production deployment or external package publication")
    if target_branch.strip() in PROTECTED_BRANCHES and any(tok in (command or "") for tok in ("push", "merge", "reset", "rebase")):
        reasons.append(f"mutates protected branch '{target_branch.strip()}'")

    if not reasons:
        return {"allowed": True, "requires_approval": False, "reasons": []}
    if operator_approved:
        return {"allowed": True, "requires_approval": True, "approved": True, "reasons": reasons}
    return {
        "allowed": False,
        "requires_approval": True,
        "approved": False,
        "reasons": reasons,
        "message": "Explicit operator permission is required: " + "; ".join(reasons),
    }


def analyze_traceback(stderr_text: str) -> dict[str, Any]:
    """Parse a Python stack trace into frames, exception class, message & root location."""
    lines = (stderr_text or "").strip().splitlines()
    frames: list[dict[str, Any]] = []
    exc_type = ""
    exc_message = ""
    for idx, line in enumerate(lines):
        match = _TRACEBACK_FRAME_RE.match(line)
        if match:
            code_line = lines[idx + 1].strip() if idx + 1 < len(lines) and not _TRACEBACK_FRAME_RE.match(lines[idx + 1]) else ""
            frames.append(
                {
                    "file": match.group(1),
                    "line": int(match.group(2)),
                    "function": match.group(3),
                    "code": code_line,
                }
            )
    for line in reversed(lines):
        stripped = line.strip()
        if ":" in stripped and not stripped.startswith("File "):
            head, _, tail = stripped.partition(":")
            if head.isidentifier() and (head.endswith(("Error", "Exception", "Warning")) or head in {"AssertionError", "SystemExit", "KeyError", "ValueError", "TypeError"}):
                exc_type = head
                exc_message = tail.strip()
                break
        elif stripped in {"AssertionError", "KeyboardInterrupt"}:
            exc_type = stripped
            break
    culprit = frames[-1] if frames else None
    return {
        "has_traceback": bool(frames or exc_type),
        "exception_type": exc_type,
        "exception_message": exc_message,
        "frame_count": len(frames),
        "frames": frames,
        "root_location": culprit,
    }


@dataclass
class DeveloperWorkspace:
    """§100 Local repository and software-engineering workspace."""

    repo_root: Path
    sandbox: Sandbox = field(default_factory=Sandbox)

    def __post_init__(self) -> None:
        self.repo_root = Path(self.repo_root).resolve()

    def git_status_and_diff(self, *, max_diff_chars: int = 16_000) -> dict[str, Any]:
        code_b, branch_out, _ = _run_git(self.repo_root, ["branch", "--show-current"])
        code_s, status_out, err_s = _run_git(self.repo_root, ["status", "--porcelain=v1"])
        if code_s != 0:
            return {"is_git_repo": False, "error": err_s.strip() or "not a git repository"}
        _, diff_out, _ = _run_git(self.repo_root, ["diff", "--no-color"])
        modified: list[dict[str, str]] = []
        for raw_line in status_out.splitlines():
            if len(raw_line) >= 4:
                modified.append({"status": raw_line[:2].strip(), "path": raw_line[3:].strip()})
        return {
            "is_git_repo": True,
            "branch": branch_out.strip() if code_b == 0 else "",
            "clean": len(modified) == 0,
            "changed_files": modified,
            "diff": diff_out[:max_diff_chars],
            "diff_truncated": len(diff_out) > max_diff_chars,
        }

    def search_repository(self, query: str, *, max_hits: int = 50) -> dict[str, Any]:
        needle = (query or "").strip()
        if not needle:
            return {"query": query, "hits": [], "symbols": []}
        lowered = needle.lower()
        hits: list[dict[str, Any]] = []
        symbols: list[dict[str, Any]] = []
        for path in sorted(self.repo_root.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(self.repo_root)
            if is_excluded(rel, excluded_dirs=DEFAULT_EXCLUDED_DIRS):
                continue
            if path.stat().st_size > 1_048_576:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if path.suffix in {".py", ".js", ".ts"}:
                for sym_name, sym_kind, sym_line in extract_symbols(text):
                    if lowered in sym_name.lower():
                        symbols.append({"symbol": sym_name, "kind": sym_kind, "file": str(rel), "line": sym_line})
            for line_no, line in enumerate(text.splitlines(), start=1):
                if lowered in line.lower():
                    hits.append({"file": str(rel), "line": line_no, "preview": line.strip()[:180]})
                    if len(hits) >= max_hits:
                        return {"query": query, "hits": hits, "symbols": symbols[:max_hits]}
        return {"query": query, "hits": hits, "symbols": symbols[:max_hits]}

    def inspect_dependencies(self) -> dict[str, Any]:
        """Inspect Python & Node dependency manifests and flag security/pinning issues (§100)."""
        manifests: list[str] = []
        packages: list[dict[str, Any]] = []
        security_warnings: list[str] = []

        for req_file in sorted(self.repo_root.glob("requirements*.txt")):
            manifests.append(req_file.name)
            for raw in req_file.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw.split("#", 1)[0].strip()
                if not line or line.startswith("-r"):
                    continue
                if "http://" in line:
                    security_warnings.append(f"{req_file.name}: insecure HTTP package index/source in '{line}'")
                if line.startswith("git+") and "@" not in line.split("//", 1)[-1]:
                    security_warnings.append(f"{req_file.name}: unpinned VCS dependency '{line}'")
                pinned = any(op in line for op in ("==", ">=", "~="))
                if not pinned:
                    security_warnings.append(f"{req_file.name}: unpinned requirement '{line}'")
                packages.append({"manifest": req_file.name, "spec": line, "constrained": pinned})

        pkg_json = self.repo_root / "package.json"
        if pkg_json.is_file():
            import json

            manifests.append("package.json")
            try:
                parsed = json.loads(pkg_json.read_text(encoding="utf-8"))
                for section in ("dependencies", "devDependencies"):
                    for name, ver in (parsed.get(section) or {}).items():
                        if str(ver).strip() in {"*", "latest"}:
                            security_warnings.append(f"package.json: floating version '{ver}' on '{name}'")
                        packages.append({"manifest": "package.json", "spec": f"{name}@{ver}", "constrained": str(ver) not in {"*", "latest"}})
            except ValueError:
                security_warnings.append("package.json could not be parsed as valid JSON")

        return {
            "manifests": manifests,
            "dependency_count": len(packages),
            "dependencies": packages[:200],
            "security_warnings": security_warnings,
        }

    def inspect_dev_environment(self) -> dict[str, Any]:
        """Prefer project-local .venv / node_modules over system-wide installation (§100)."""
        venv_dir = self.repo_root / ".venv"
        venv_python = venv_dir / "bin" / "python"
        node_local = self.repo_root / "node_modules" / ".bin"
        return {
            "repo_root": str(self.repo_root),
            "project_local_venv_present": venv_python.is_file(),
            "preferred_python": str(venv_python) if venv_python.is_file() else sys.executable,
            "system_wide_install_recommended": False,
            "node_local_bin_present": node_local.is_dir(),
            "container_runtime_available": bool(shutil.which("podman") or shutil.which("docker")),
            "container_required_for_basic_features": False,
        }

    def discover_tests(self) -> dict[str, Any]:
        tests_dir = self.repo_root / "tests"
        files: list[str] = []
        test_functions = 0
        if tests_dir.is_dir():
            for path in sorted(tests_dir.rglob("test_*.py")):
                files.append(str(path.relative_to(self.repo_root)))
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                test_functions += sum(
                    1 for line in text.splitlines() if line.lstrip().startswith(("def test_", "async def test_"))
                )
        return {"test_files": files, "file_count": len(files), "discovered_test_functions": test_functions}

    def inspect_deployment_configs(self) -> dict[str, Any]:
        found: list[dict[str, Any]] = []
        candidates = [
            self.repo_root / "Dockerfile",
            self.repo_root / "packaging" / "debian" / "control",
            *sorted((self.repo_root.parent / ".github" / "workflows").glob("*.yml")),
            *sorted((self.repo_root / ".github" / "workflows").glob("*.yml")),
        ]
        seen: set[Path] = set()
        for path in candidates:
            resolved = path.resolve()
            if resolved in seen or not path.is_file():
                continue
            seen.add(resolved)
            found.append({"path": str(path), "bytes": path.stat().st_size})
        return {"configs": found, "count": len(found)}

    def evaluate_candidate_patch(
        self,
        *,
        staging_root: Path,
        relative_file: str,
        updated_content: str,
        test_code: str,
    ) -> dict[str, Any]:
        """Test an isolated candidate patch inside the sandbox without touching the live working tree (§100)."""
        stage = Path(staging_root).resolve()
        if stage == self.repo_root or self.repo_root.is_relative_to(stage):
            raise ValueError("staging_root must be isolated from repo_root")
        stage.mkdir(parents=True, exist_ok=True)
        target = (stage / relative_file).resolve()
        if not target.is_relative_to(stage):
            raise PermissionError("relative_file escapes staging_root")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(updated_content, encoding="utf-8")

        runner = stage / "_run_candidate_check.py"
        runner.write_text(test_code, encoding="utf-8")

        env_py = str(self.repo_root / ".venv" / "bin" / "python") if (self.repo_root / ".venv" / "bin" / "python").is_file() else sys.executable
        run = self.sandbox.run(
            [env_py, str(runner)],
            risk=RISK_GENERATED_CODE,
            policy=SandboxPolicy(
                writable_roots=(str(stage),),
                network=False,
                timeout_seconds=20.0,
                cwd=str(stage),
            ),
        )
        passed = run.status == STATUS_COMPLETED and run.exit_code == 0
        tb = analyze_traceback(run.stderr) if not passed else {"has_traceback": False}
        return {
            "passed": passed,
            "working_tree_untouched": True,
            "sandbox_mechanism": run.mechanism,
            "exit_code": run.exit_code,
            "stdout": run.stdout,
            "stderr": run.stderr,
            "traceback": tb,
        }


__all__ = [
    "PROTECTED_BRANCHES",
    "DeveloperWorkspace",
    "analyze_traceback",
    "check_git_or_deploy_action",
]
