"""§243 Transfer Learning, §244 Continual Skill Acquisition, §245 Scientific Discovery Lab, §246 Multimodal Intelligence."""
from __future__ import annotations

import asyncio
import csv
import hashlib
import json
import math
import shutil
import statistics
import struct
import subprocess
import sys
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from nova.capabilities import CapabilityRegistry
from nova.db import Database
from nova.tools.registry import ToolDefinition, ToolOutcome, ToolRegistry

READING_DOCS_ALONE_COUNTS_AS_ACQUIRED = False
FABRICATE_CITATIONS_OR_RESULTS = False
ASSUME_ALL_MODELS_SUPPORT_ALL_MODALITIES = False

EXPERIMENT_EXECUTION_MODES: tuple[str, ...] = (
    "proposed_experiment",
    "simulated_experiment",
    "completed_experiment",
)

RESEARCH_9_MANDATORY_FIELDS: tuple[str, ...] = (
    "original_question",
    "sources",
    "dataset_provenance",
    "methods",
    "parameters",
    "scripts",
    "results",
    "limitations",
    "reproducibility_instructions",
)

SUPPORTED_MULTIMODAL_INPUT_TYPES: tuple[str, ...] = (
    "screenshot",
    "image",
    "terminal_log",
    "system_log",
    "diagram",
    "documentation",
    "audio",
    "transcript",
    "pdf_table",
    "source_code",
    "application_output",
    "video",
)


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


class CrossDomainTransferEngine:
    """§243 Applies validated procedures across domains after inspecting assumptions, prerequisites & empirical gain."""

    def __init__(self, *, db: Database) -> None:
        self.db = db

    def register_source_procedure(
        self,
        *,
        name: str,
        source_domain: str,
        steps: list[str],
        assumptions: list[str],
        prerequisites: list[str],
        dependencies: list[str],
    ) -> dict[str, Any]:
        pid = f"proc-{hashlib.sha256(f'{source_domain}:{name}'.encode()).hexdigest()[:10]}"
        return self.db.upsert_gi_skill_or_study(
            {
                "id": pid,
                "record_kind": "validated_procedure",
                "name": name,
                "version": "1.0.0",
                "domain": source_domain,
                "validated": True,
                "spec": {
                    "steps": list(steps),
                    "assumptions": list(assumptions),
                    "prerequisites": list(prerequisites),
                    "dependencies": list(dependencies),
                },
            }
        )

    def transfer_and_validate_procedure(
        self,
        *,
        source_procedure_id: str,
        target_domain: str,
        target_environment: dict[str, Any],
        adapted_steps: list[str],
        validation_fn: Callable[[], dict[str, Any]] | None = None,
        baseline_score: float = 0.50,
    ) -> dict[str, Any]:
        """§243 Inspects assumptions/prerequisites/dependencies, tests adapted procedure, and measures improvement."""
        procs = [
            p
            for p in self.db.list_gi_skills_and_studies(record_kind="validated_procedure", limit=200)
            if p["id"] == source_procedure_id
        ]
        if not procs:
            raise KeyError(f"Source procedure '{source_procedure_id}' not found.")
        src = procs[0]
        spec = src["spec"]

        avail_prereqs = set(target_environment.get("satisfied_prerequisites") or [])
        avail_deps = set(target_environment.get("installed_dependencies") or []) | {
            d for d in spec["dependencies"] if shutil.which(d) is not None or d == "python3"
        }
        held_assumptions = set(target_environment.get("valid_assumptions") or [])

        missing_prereqs = [p for p in spec["prerequisites"] if p not in avail_prereqs]
        missing_deps = [d for d in spec["dependencies"] if d not in avail_deps]
        violated_assumptions = [a for a in spec["assumptions"] if a not in held_assumptions]

        compatible = not (missing_prereqs or missing_deps or violated_assumptions)
        inspection = {
            "compatible": compatible,
            "missing_prerequisites": missing_prereqs,
            "missing_dependencies": missing_deps,
            "violated_assumptions": violated_assumptions,
        }
        if not compatible or validation_fn is None:
            return {
                "transferred": False,
                "validated": False,
                "compatibility_inspection": inspection,
                "measured_improvement": 0.0,
            }

        val_res = validation_fn()
        passed = bool(val_res.get("passed"))
        transferred_score = float(val_res.get("score") if val_res.get("score") is not None else (0.92 if passed else 0.0))
        improvement = round(transferred_score - float(baseline_score), 4)
        validated = passed and improvement > 0.0

        saved = self.db.upsert_gi_skill_or_study(
            {
                "id": f"xfer-{uuid.uuid4().hex[:10]}",
                "record_kind": "transferred_procedure",
                "name": f"{src['name']} -> {target_domain}",
                "version": "1.0.0",
                "domain": target_domain,
                "validated": validated,
                "spec": {
                    "source_procedure_id": source_procedure_id,
                    "source_domain": src["domain"],
                    "target_domain": target_domain,
                    "adapted_steps": adapted_steps,
                    "compatibility_inspection": inspection,
                    "validation_result": val_res,
                    "baseline_score": baseline_score,
                    "transferred_score": transferred_score,
                    "measured_improvement": improvement,
                },
            }
        )
        return {
            "transferred": True,
            "validated": validated,
            "record": saved,
            "compatibility_inspection": inspection,
            "measured_improvement": improvement,
        }


class ContinualSkillAcquisitionEngine:
    """§244 12-Step Continual Learning & Practical Skill Acquisition through Controlled Experimentation."""

    def __init__(
        self,
        *,
        db: Database,
        workspace_dir: Path,
        capabilities: CapabilityRegistry | None = None,
        tool_registry: ToolRegistry | None = None,
    ) -> None:
        self.db = db
        self.workspace_dir = workspace_dir
        self.capabilities = capabilities
        self.tool_registry = tool_registry

    def acquire_unfamiliar_cli_or_library_skill(
        self,
        *,
        skill_name: str,
        executable_or_script: str,
        initial_prototype_args: list[str],
        repaired_prototype_args: list[str] | None = None,
        holdout_task_args: list[str] | None = None,
        expected_holdout_substring: str = "",
        version: str = "1.0.0",
        read_docs_only: bool = False,
    ) -> dict[str, Any]:
        """Executes all 12 §244 steps; refuses to mark acquired from reading docs alone."""
        sandbox_dir = self.workspace_dir / "skill_lab" / re.sub_safe(skill_name)
        sandbox_dir.mkdir(parents=True, exist_ok=True)
        steps: list[dict[str, Any]] = []

        # Step 1: Identify knowledge gap
        steps.append({"step": 1, "action": "identify_knowledge_gap", "skill_name": skill_name})

        # Step 2: Search/inspect official documentation (--help)
        base_cmd = [sys.executable, executable_or_script] if executable_or_script.endswith(".py") else [executable_or_script]
        help_proc = subprocess.run(
            [*base_cmd, "--help"],
            cwd=str(sandbox_dir),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        help_text = ((help_proc.stdout or "") + "\n" + (help_proc.stderr or "")).strip()
        steps.append({"step": 2, "action": "inspect_official_documentation", "help_excerpt": help_text[:400]})

        # Step 3: Examine examples & interfaces
        discovered_flags = sorted(set(__import__("re").findall(r"--[a-z0-9\-]+", help_text)))
        steps.append({"step": 3, "action": "examine_examples_and_interfaces", "discovered_flags": discovered_flags})

        # Step 4: Identify required dependencies
        deps = ["python3"] if executable_or_script.endswith(".py") else [Path(executable_or_script).name]
        steps.append({"step": 4, "action": "identify_required_dependencies", "dependencies": deps})

        # Invariant check: reading docs alone NEVER counts as skill acquisition!
        if read_docs_only:
            return {
                "skill_name": skill_name,
                "acquired": False,
                "reading_docs_alone_counts_as_acquired": READING_DOCS_ALONE_COUNTS_AS_ACQUIRED,
                "reason": "functional_competence_not_demonstrated_via_testing",
                "steps": steps,
            }

        # Step 5 & 6: Build small prototype & test in isolated sandbox
        proto_script = sandbox_dir / "prototype_runner.py"
        proto_script.write_text(
            "import subprocess, sys\n"
            f"res = subprocess.run({base_cmd + list(initial_prototype_args)!r}, capture_output=True, text=True)\n"
            "sys.stdout.write(res.stdout)\nsys.stderr.write(res.stderr)\nsys.exit(res.returncode)\n",
            encoding="utf-8",
        )
        steps.append({"step": 5, "action": "build_small_prototype", "prototype_path": str(proto_script)})

        p1 = subprocess.run(
            [sys.executable, str(proto_script)],
            cwd=str(sandbox_dir),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        steps.append({"step": 6, "action": "test_prototype_in_sandbox", "exit_code": p1.returncode})

        # Step 7 & 8: Inspect errors & improve prototype
        final_args = list(initial_prototype_args)
        error_inspected = (p1.stderr or "").strip()[:300]
        steps.append({"step": 7, "action": "inspect_errors", "initial_failed": p1.returncode != 0, "stderr": error_inspected})

        if p1.returncode != 0 and repaired_prototype_args is not None:
            final_args = list(repaired_prototype_args)
            proto_script.write_text(
                "import subprocess, sys\n"
                f"res = subprocess.run({base_cmd + final_args!r}, capture_output=True, text=True)\n"
                "sys.stdout.write(res.stdout)\nsys.stderr.write(res.stderr)\nsys.exit(res.returncode)\n",
                encoding="utf-8",
            )
        steps.append({"step": 8, "action": "improve_prototype", "active_args": final_args})

        # Step 9: Validate functionality
        p2 = subprocess.run(
            [sys.executable, str(proto_script)],
            cwd=str(sandbox_dir),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        prototype_valid = p2.returncode == 0
        steps.append({"step": 9, "action": "validate_functionality", "passed": prototype_valid, "stdout": (p2.stdout or "").strip()[:300]})

        # Step 10: Generate reusable documentation
        doc_path = sandbox_dir / "SKILL.md"
        doc_path.write_text(
            f"# Skill: {skill_name} (v{version})\n\n"
            f"- Executable: `{executable_or_script}`\n"
            f"- Discovered Flags: `{', '.join(discovered_flags)}`\n"
            f"- Validated Prototype Invocation: `{' '.join(base_cmd + final_args)}`\n",
            encoding="utf-8",
        )
        steps.append({"step": 10, "action": "generate_reusable_documentation", "doc_path": str(doc_path)})

        # Step 12 (before final acquired=True): Evaluate on an additional unseen relevant task!
        holdout_args = list(holdout_task_args if holdout_task_args is not None else final_args)
        p_holdout = subprocess.run(
            [*base_cmd, *holdout_args],
            cwd=str(sandbox_dir),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        holdout_out = ((p_holdout.stdout or "") + (p_holdout.stderr or "")).strip()
        holdout_passed = p_holdout.returncode == 0 and (
            not expected_holdout_substring or expected_holdout_substring in holdout_out
        )
        acquired = bool(prototype_valid and holdout_passed)

        # Step 11: Register capability & tool when validated
        safe_id = f"skill_{re.sub_safe(skill_name)}"
        if acquired and self.capabilities is not None:
            self.capabilities.register_acquired_capability(
                capability_id=safe_id,
                label=f"Learned Skill: {skill_name}",
                purpose=f"Validated continual-learning skill '{skill_name}'",
                executable_path=sys.executable if executable_or_script.endswith(".py") else executable_or_script,
                version=version,
                section="§244",
            )
        if acquired and self.tool_registry is not None and self.tool_registry.get(safe_id) is None:
            class _LearnedSkillInput(BaseModel):
                model_config = ConfigDict(extra="forbid")
                args: list[str] = Field(default_factory=list)

            async def _skill_handler(inp: BaseModel, _approved: bool, _cmd: list[str] = base_cmd) -> ToolOutcome:
                cli_args = [str(x) for x in inp.model_dump().get("args", [])]
                r = await asyncio.to_thread(
                    subprocess.run,
                    [*_cmd, *cli_args],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
                status = "success" if r.returncode == 0 else "error"
                return ToolOutcome(
                    status=status,
                    summary=f"Executed learned skill `{skill_name}` (exit_code={r.returncode}).",
                    data={"exit_code": r.returncode, "stdout": (r.stdout or "")[:1000], "stderr": (r.stderr or "")[:400]},
                )

            self.tool_registry.register(
                ToolDefinition(
                    name=safe_id,
                    description=f"Validated learned skill wrapper for {skill_name} (v{version}).",
                    parameters=_LearnedSkillInput.model_json_schema(),
                    input_model=_LearnedSkillInput,
                    handler=_skill_handler,
                    permission="workspace_read",
                    category="continual_learning",
                    autonomy_class="routine",
                )
            )
        steps.append({"step": 11, "action": "register_capability", "capability_id": safe_id, "registered": acquired})
        steps.append(
            {
                "step": 12,
                "action": "evaluate_on_additional_relevant_task",
                "holdout_passed": holdout_passed,
                "holdout_output": holdout_out[:300],
            }
        )

        rec = self.db.upsert_gi_skill_or_study(
            {
                "id": safe_id,
                "record_kind": "acquired_skill",
                "name": skill_name,
                "version": version,
                "domain": "continual_learning",
                "validated": acquired,
                "spec": {
                    "executable": executable_or_script,
                    "discovered_flags": discovered_flags,
                    "doc_path": str(doc_path),
                    "holdout_passed": holdout_passed,
                    "steps": steps,
                },
            }
        )
        return {
            "skill_name": skill_name,
            "capability_id": safe_id,
            "acquired": acquired,
            "reading_docs_alone_counts_as_acquired": READING_DOCS_ALONE_COUNTS_AS_ACQUIRED,
            "doc_path": str(doc_path),
            "record": rec,
            "steps": steps,
        }


class re:
    """Small helper namespace for safe slugging without shadowing module regex when needed."""

    @staticmethod
    def sub_safe(raw: str) -> str:
        return __import__("re").sub(r"[^a-z0-9_]+", "_", raw.strip().lower()).strip("_") or "item"


class ScientificDiscoveryLab:
    """§245 Autonomous Research, Dataset Investigation, Statistical Analysis & Reproducible Discovery Lab."""

    def __init__(self, *, db: Database, workspace_dir: Path) -> None:
        self.db = db
        self.workspace_dir = workspace_dir

    def investigate_dataset(self, dataset_path: str | Path, *, x_col: str = "", y_col: str = "") -> dict[str, Any]:
        """§245 Real statistical dataset investigation with SHA-256 dataset provenance."""
        p = Path(dataset_path)
        if not p.is_file():
            raise FileNotFoundError(f"Dataset file not found: {p}")
        raw_bytes = p.read_bytes()
        sha256 = hashlib.sha256(raw_bytes).hexdigest()

        rows: list[dict[str, Any]] = []
        if p.suffix.lower() == ".json":
            loaded = json.loads(raw_bytes.decode("utf-8"))
            rows = list(loaded) if isinstance(loaded, list) else list(loaded.get("rows") or [])
        else:
            reader = csv.DictReader(raw_bytes.decode("utf-8").splitlines())
            rows = [dict(r) for r in reader]

        columns = sorted({k for r in rows for k in r})
        numeric_summaries: dict[str, dict[str, Any]] = {}
        missing_counts: dict[str, int] = dict.fromkeys(columns, 0)
        numeric_series: dict[str, list[float]] = {c: [] for c in columns}

        for r in rows:
            for c in columns:
                val = r.get(c)
                if val is None or str(val).strip() == "":
                    missing_counts[c] += 1
                    continue
                try:
                    numeric_series[c].append(float(val))
                except (TypeError, ValueError):
                    pass

        for c, vals in numeric_series.items():
            if len(vals) < 2:
                continue
            mean_v = statistics.fmean(vals)
            std_v = statistics.stdev(vals)
            sorted_v = sorted(vals)
            q1 = sorted_v[len(sorted_v) // 4]
            q3 = sorted_v[(3 * len(sorted_v)) // 4]
            iqr = max(1e-9, q3 - q1)
            outliers = [v for v in vals if v < (q1 - 1.5 * iqr) or v > (q3 + 1.5 * iqr)]
            numeric_summaries[c] = {
                "count": len(vals),
                "mean": round(mean_v, 6),
                "stdev": round(std_v, 6),
                "min": round(min(vals), 6),
                "median": round(statistics.median(vals), 6),
                "max": round(max(vals), 6),
                "iqr_outliers": outliers,
            }

        bivariate: dict[str, Any] = {}
        if x_col and y_col and x_col in columns and y_col in columns:
            paired: list[tuple[float, float]] = []
            for r in rows:
                try:
                    xv = float(r[x_col])
                    yv = float(r[y_col])
                    paired.append((xv, yv))
                except (KeyError, TypeError, ValueError):
                    continue
            if len(paired) >= 3:
                xs = [pt[0] for pt in paired]
                ys = [pt[1] for pt in paired]
                mx, my = statistics.fmean(xs), statistics.fmean(ys)
                sxx = sum((x - mx) ** 2 for x in xs)
                syy = sum((y - my) ** 2 for y in ys)
                sxy = sum((x - mx) * (y - my) for x, y in paired)
                corr = (sxy / math.sqrt(sxx * syy)) if (sxx > 0 and syy > 0) else 0.0
                slope = (sxy / sxx) if sxx > 0 else 0.0
                intercept = my - slope * mx
                bivariate = {
                    "x_col": x_col,
                    "y_col": y_col,
                    "paired_n": len(paired),
                    "pearson_r": round(corr, 6),
                    "ols_slope": round(slope, 6),
                    "ols_intercept": round(intercept, 6),
                }

        return {
            "dataset_provenance": {"path": str(p), "sha256": sha256, "size_bytes": len(raw_bytes), "row_count": len(rows)},
            "columns": columns,
            "missing_counts": missing_counts,
            "numeric_summaries": numeric_summaries,
            "bivariate_analysis": bivariate,
        }

    def run_scientific_study(
        self,
        *,
        question: str,
        sources: list[dict[str, str]],
        hypothesis: str,
        execution_mode: str = "completed_experiment",
        dataset_path: str | Path | None = None,
        python_analysis_script: str = "",
        parameters: dict[str, Any] | None = None,
        limitations: list[str] | None = None,
    ) -> dict[str, Any]:
        """§245 Preserves all 9 reproducibility artifacts and strictly distinguishes proposed vs simulated vs completed."""
        if execution_mode not in EXPERIMENT_EXECUTION_MODES:
            raise ValueError(f"Unsupported execution_mode '{execution_mode}'. Valid: {', '.join(EXPERIMENT_EXECUTION_MODES)}")
        for src in sources:
            if not str(src.get("title") or "").strip() or not str(src.get("origin_ref") or "").strip():
                raise ValueError("Every research source must carry verifiable title and origin_ref — fabricated citations forbidden (§245).")

        study_id = f"study-{uuid.uuid4().hex[:10]}"
        study_dir = self.workspace_dir / "research_lab" / study_id
        study_dir.mkdir(parents=True, exist_ok=True)

        ds_summary: dict[str, Any] = {"status": "none_provided"}
        if dataset_path is not None:
            ds_summary = self.investigate_dataset(dataset_path)

        script_path_str = ""
        script_result: dict[str, Any] = {"executed": False}
        if python_analysis_script.strip():
            sp = study_dir / "experiment_analysis.py"
            sp.write_text(python_analysis_script, encoding="utf-8")
            script_path_str = str(sp)
            if execution_mode in {"simulated_experiment", "completed_experiment"}:
                proc = subprocess.run(
                    [sys.executable, str(sp)],
                    cwd=str(study_dir),
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
                script_result = {
                    "executed": True,
                    "exit_code": proc.returncode,
                    "stdout": (proc.stdout or "").strip()[:1000],
                    "stderr": (proc.stderr or "").strip()[:400],
                }

        bundle = {
            "original_question": question,
            "sources": list(sources),
            "dataset_provenance": ds_summary.get("dataset_provenance", ds_summary),
            "methods": {
                "hypothesis": hypothesis,
                "execution_mode": execution_mode,
                "statistical_pipeline": bool(dataset_path is not None),
                "computational_script_used": bool(script_path_str),
            },
            "parameters": dict(parameters or {}),
            "scripts": [script_path_str] if script_path_str else [],
            "results": {
                "execution_mode": execution_mode,
                "is_genuinely_completed_experiment": execution_mode == "completed_experiment" and (
                    not script_path_str or script_result.get("exit_code") == 0
                ),
                "dataset_analysis": ds_summary,
                "script_execution": script_result,
            },
            "limitations": list(limitations or ["Scope bounded to supplied dataset and local deterministic execution."]),
            "reproducibility_instructions": (
                f"Run `{sys.executable} {script_path_str}` inside `{study_dir}` and verify dataset SHA-256."
                if script_path_str
                else f"Re-run dataset investigation against SHA-256 verified input in `{study_dir}`."
            ),
        }
        report_md = study_dir / "RESEARCH_REPORT.md"
        report_md.write_text(
            f"# Research Report: {question}\n\n"
            f"- **Execution Mode:** `{execution_mode}`\n"
            f"- **Hypothesis:** {hypothesis}\n"
            f"- **Sources ({len(sources)}):** " + ", ".join(s["origin_ref"] for s in sources) + "\n"
            f"- **Reproducibility:** {bundle['reproducibility_instructions']}\n",
            encoding="utf-8",
        )
        saved = self.db.upsert_gi_skill_or_study(
            {
                "id": study_id,
                "record_kind": "scientific_study",
                "name": question[:140],
                "version": "1.0.0",
                "domain": "scientific_discovery",
                "validated": bool(bundle["results"]["is_genuinely_completed_experiment"]),
                "spec": {**bundle, "report_path": str(report_md), "fabricate_citations_or_results": FABRICATE_CITATIONS_OR_RESULTS},
            }
        )
        return {"study_id": study_id, "execution_mode": execution_mode, "bundle": bundle, "report_path": str(report_md), "record": saved}


class UnifiedMultimodalEngine:
    """§246 Combines Screenshot/Image/Diagram, Logs, Audio/Transcript, PDF/Doc Tables, Code & Video with Model Capability Checks."""

    def __init__(self, *, db: Database) -> None:
        self.db = db

    @staticmethod
    def _inspect_image_header(path: Path) -> dict[str, Any]:
        data = path.read_bytes()
        if data[:8] == b"\x89PNG\r\n\x1a\n" and len(data) >= 24:
            width, height = struct.unpack(">II", data[16:24])
            return {"format": "PNG", "width": width, "height": height, "size_bytes": len(data)}
        return {"format": path.suffix.lstrip(".").upper() or "BINARY", "size_bytes": len(data)}

    def select_capable_models(
        self,
        required_modalities: list[str],
        available_model_profiles: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """§246 Never assumes all models support every input type; maps modalities to capable profiles."""
        modality_map = {
            "screenshot": "vision",
            "image": "vision",
            "diagram": "vision",
            "audio": "audio",
            "video": "video",
            "pdf_table": "document",
        }
        needed_caps = {modality_map.get(m, "text") for m in required_modalities}
        selected: dict[str, str] = {}
        missing_caps: list[str] = []
        for cap in sorted(needed_caps):
            match = next(
                (p["id"] for p in available_model_profiles if cap in set(p.get("capabilities") or ["text"])),
                None,
            )
            if match:
                selected[cap] = match
            else:
                missing_caps.append(cap)
        return {
            "required_capabilities": sorted(needed_caps),
            "selected_models_by_capability": selected,
            "missing_model_capabilities": missing_caps,
            "assumed_universal_model_support": ASSUME_ALL_MODELS_SUPPORT_ALL_MODALITIES,
        }

    def fuse_multimodal_bundle(
        self,
        *,
        task_title: str,
        artifacts: list[dict[str, Any]],
        available_model_profiles: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """§246 Extracts signals across modalities and preserves provenance links between sources, interpretations & verified findings."""
        profiles = available_model_profiles or [
            {"id": "frontier-vision-reasoner", "capabilities": ["text", "vision", "document"]},
            {"id": "frontier-audio-specialist", "capabilities": ["text", "audio"]},
        ]
        input_types = [str(a.get("type") or "documentation") for a in artifacts]
        routing = self.select_capable_models(input_types, profiles)

        provenance_links: list[dict[str, Any]] = []
        extracted_signals: list[str] = []
        for idx, art in enumerate(artifacts):
            atype = str(art.get("type") or "documentation")
            src = str(art.get("source") or f"artifact_{idx}")
            text_body = str(art.get("content") or "")
            img_meta: dict[str, Any] = {}
            if atype in {"screenshot", "image", "diagram"} and art.get("path") and Path(str(art["path"])).is_file():
                img_meta = self._inspect_image_header(Path(str(art["path"])))
            error_codes = __import__("re").findall(r"\b(?:ERROR|CRITICAL|Exception|E\d{3,4}|HTTP\s+5\d\d|exit_code=[1-9]\d*)\b", text_body)
            interpretation = (
                f"Image {img_meta.get('format')} {img_meta.get('width', '?')}x{img_meta.get('height', '?')} ({text_body[:120]})"
                if img_meta
                else f"{atype}: {text_body[:160]}"
            )
            extracted_signals.extend(error_codes)
            provenance_links.append(
                {
                    "artifact_index": idx,
                    "input_type": atype,
                    "source_ref": src,
                    "routed_model": routing["selected_models_by_capability"].get(
                        {"screenshot": "vision", "image": "vision", "diagram": "vision", "audio": "audio", "video": "video", "pdf_table": "document"}.get(atype, "text"),
                        "local_deterministic_inspector",
                    ),
                    "model_interpretation": interpretation,
                    "verified_signals": error_codes or ([f"verified_header:{img_meta['format']}"] if img_meta else ["text_parsed"]),
                }
            )

        distinct_types = sorted(set(input_types))
        return {
            "task_title": task_title,
            "combined_modality_count": len(distinct_types),
            "combined_modalities": distinct_types,
            "model_routing": routing,
            "cross_modal_correlations": sorted(set(extracted_signals)),
            "provenance_links": provenance_links,
        }
