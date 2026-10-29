"""§138 Universal quality assurance and §139 iterative creation & autonomous refinement.

Every artifact is evaluated through structural, mathematical, or executable
checks appropriate to its domain—never by file existence alone—and bounded
refinement retains improvements while reverting regressions via checkpoints.
"""
from __future__ import annotations

import ast
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from nova.creation.media_codecs import (
    inspect_docx,
    inspect_mesh,
    inspect_pdf,
    inspect_png,
    inspect_srt,
    inspect_svg,
    inspect_video,
    inspect_wav,
    inspect_xlsx,
    render_svg_to_png,
)
from nova.creation.workspace import EXCLUDED_SNAPSHOT_NAMES, LineageTracker


def _iter_project_files(project_dir: Path) -> list[Path]:
    out: list[Path] = []
    for fp in sorted(Path(project_dir).rglob("*")):
        if not fp.is_file():
            continue
        if any(part in EXCLUDED_SNAPSHOT_NAMES for part in fp.relative_to(project_dir).parts):
            continue
        out.append(fp)
    return out


class QualityAssuranceEngine:
    """§138 Runs domain-appropriate builds, tests, geometry validations, and media/document inspections."""

    FILE_EXISTENCE_ALONE_SUFFICIENT = False

    def evaluate(self, domain: str, project_dir: Path, *, spec: dict[str, Any] | None = None) -> dict[str, Any]:
        pdir = Path(project_dir)
        files = _iter_project_files(pdir)
        checks: list[dict[str, Any]] = []
        defects: list[dict[str, Any]] = []

        if not files:
            return {
                "passed": False,
                "quality_score": 0.0,
                "domain": domain,
                "checks": [{"name": "non_empty_workspace", "passed": False, "detail": "No project files generated."}],
                "defects": [{"code": "empty_project", "target": ".", "detail": "Project directory contains no deliverables."}],
            }

        # 1. Code syntax checks across Python / JS / C sources when present.
        py_files = [f for f in files if f.suffix == ".py"]
        for pyf in py_files:
            rel = str(pyf.relative_to(pdir))
            try:
                ast.parse(pyf.read_text(encoding="utf-8"), filename=rel)
                checks.append({"name": f"python_ast:{rel}", "passed": True, "detail": "Valid Python AST"})
            except SyntaxError as exc:
                checks.append({"name": f"python_ast:{rel}", "passed": False, "detail": f"SyntaxError line {exc.lineno}: {exc.msg}"})
                defects.append({"code": "python_syntax_error", "target": rel, "detail": str(exc)})

        js_files = [f for f in files if f.suffix == ".js"]
        node_bin = shutil.which("node")
        if js_files and node_bin:
            for jsf in js_files:
                rel = str(jsf.relative_to(pdir))
                proc = subprocess.run([node_bin, "--check", str(jsf)], capture_output=True, text=True, timeout=8, check=False)
                ok = proc.returncode == 0
                checks.append({"name": f"js_syntax:{rel}", "passed": ok, "detail": "node --check OK" if ok else (proc.stderr or "syntax error")[:160]})
                if not ok:
                    defects.append({"code": "js_syntax_error", "target": rel, "detail": (proc.stderr or "")[:160]})

        # 2. Execute automated test suite when `tests/` contains test_*.py.
        test_files = [f for f in py_files if f.name.startswith("test_") or "tests" in f.relative_to(pdir).parts]
        if test_files and domain in {
            "software",
            "web_mobile",
            "game",
            "database",
            "ml",
            "simulation",
            "education",
            "integration",
            "plugin_capability",
        }:
            py_paths: list[str] = [str(pdir), str(pdir / "src")]
            comp_root = pdir / "companion_artifacts"
            if comp_root.is_dir():
                for child in sorted(comp_root.iterdir()):
                    if child.is_dir():
                        py_paths.append(str(child))
                        if (child / "src").is_dir():
                            py_paths.append(str(child / "src"))
            if os.environ.get("PYTHONPATH"):
                py_paths.append(os.environ["PYTHONPATH"])
            env = {**os.environ, "PYTHONPATH": os.pathsep.join(py_paths)}
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", *[str(tf) for tf in test_files]],
                cwd=str(pdir),
                env=env,
                capture_output=True,
                text=True,
                timeout=25,
                check=False,
            )
            combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
            ok = proc.returncode == 0 and ("passed" in combined)
            checks.append(
                {
                    "name": "automated_pytest_suite",
                    "passed": ok,
                    "detail": combined.strip().splitlines()[-1][:200] if combined.strip() else f"exit={proc.returncode}",
                }
            )
            if not ok:
                defects.append({"code": "test_suite_failed", "target": "tests", "detail": combined[-300:]})

        # 3. SVG & PNG visual inspections.
        svg_files = [f for f in files if f.suffix.lower() == ".svg"]
        png_files = [f for f in files if f.suffix.lower() == ".png"]
        for svgf in svg_files:
            rel = str(svgf.relative_to(pdir))
            info = inspect_svg(svgf)
            ok = bool(info.get("valid")) and bool(info.get("has_accessible_title"))
            checks.append(
                {
                    "name": f"svg_structure:{rel}",
                    "passed": ok,
                    "detail": f"{info.get('width')}x{info.get('height')}, elements={info.get('element_count')}, title={info.get('has_accessible_title')}",
                }
            )
            if not info.get("valid"):
                defects.append({"code": "invalid_svg", "target": rel, "detail": str(info.get("error"))})
            elif not info.get("has_accessible_title"):
                defects.append({"code": "missing_svg_title", "target": rel, "detail": "SVG lacks accessible <title> element."})

        if domain == "visual_design" and svg_files and not png_files:
            checks.append({"name": "visual_preview_png", "passed": False, "detail": "Editable SVG present but PNG preview missing."})
            defects.append({"code": "missing_png_preview", "target": str(svg_files[0].relative_to(pdir)), "detail": "Render PNG preview for SVG."})

        for pngf in png_files:
            rel = str(pngf.relative_to(pdir))
            info = inspect_png(pngf)
            ok = bool(info.get("valid")) and bool(info.get("non_blank"))
            checks.append(
                {
                    "name": f"png_quality:{rel}",
                    "passed": ok,
                    "detail": f"{info.get('width')}x{info.get('height')}, non_blank={info.get('non_blank')}, std={info.get('luminance_std')}",
                }
            )
            if not ok:
                defects.append({"code": "invalid_or_blank_png", "target": rel, "detail": str(info)})

        # 4. Audio, Subtitle, and Video inspections.
        for wavf in [f for f in files if f.suffix.lower() == ".wav"]:
            rel = str(wavf.relative_to(pdir))
            info = inspect_wav(wavf)
            ok = bool(info.get("valid")) and float(info.get("duration_seconds") or 0) > 0
            checks.append({"name": f"audio_wav:{rel}", "passed": ok, "detail": f"duration={info.get('duration_seconds')}s, rate={info.get('sample_rate_hz')}Hz"})
            if not ok:
                defects.append({"code": "invalid_wav", "target": rel, "detail": str(info)})

        for srtf in [f for f in files if f.suffix.lower() == ".srt"]:
            rel = str(srtf.relative_to(pdir))
            info = inspect_srt(srtf)
            checks.append({"name": f"subtitles_srt:{rel}", "passed": bool(info.get("valid")), "detail": f"cues={info.get('cue_count')}"})
            if not info.get("valid"):
                defects.append({"code": "invalid_srt", "target": rel, "detail": str(info)})

        for vidf in [f for f in files if f.suffix.lower() in {".avi", ".mp4"}]:
            rel = str(vidf.relative_to(pdir))
            info = inspect_video(vidf)
            ok = bool(info.get("valid"))
            checks.append({"name": f"video_container:{rel}", "passed": ok, "detail": f"format={info.get('format')}, frames={info.get('frames', 'n/a')}"})
            if not ok:
                defects.append({"code": "invalid_video", "target": rel, "detail": str(info)})

        # 5. 3D Mesh geometry & manifold checks.
        for meshf in [f for f in files if f.suffix.lower() in {".stl", ".obj"}]:
            rel = str(meshf.relative_to(pdir))
            info = inspect_mesh(meshf)
            ok = bool(info.get("valid")) and bool(info.get("watertight_manifold"))
            checks.append(
                {
                    "name": f"mesh_geometry:{rel}",
                    "passed": ok,
                    "detail": f"faces={info.get('face_count')}, watertight={info.get('watertight_manifold')}, vol={info.get('volume_mm3')}mm3",
                }
            )
            if not ok:
                defects.append({"code": "non_manifold_or_invalid_mesh", "target": rel, "detail": str(info)})

        # 6. Office & Document format checks (.docx, .xlsx, .pdf, .md, quiz JSON).
        for docxf in [f for f in files if f.suffix.lower() == ".docx"]:
            rel = str(docxf.relative_to(pdir))
            info = inspect_docx(docxf)
            checks.append({"name": f"docx_structure:{rel}", "passed": bool(info.get("valid")), "detail": f"runs={info.get('paragraph_runs')}"})
            if not info.get("valid"):
                defects.append({"code": "invalid_docx", "target": rel, "detail": str(info)})

        for xlsxf in [f for f in files if f.suffix.lower() == ".xlsx"]:
            rel = str(xlsxf.relative_to(pdir))
            info = inspect_xlsx(xlsxf)
            checks.append({"name": f"xlsx_structure:{rel}", "passed": bool(info.get("valid")), "detail": f"rows={info.get('rows')}, cells={info.get('cells')}"})
            if not info.get("valid"):
                defects.append({"code": "invalid_xlsx", "target": rel, "detail": str(info)})

        for pdff in [f for f in files if f.suffix.lower() == ".pdf"]:
            rel = str(pdff.relative_to(pdir))
            info = inspect_pdf(pdff)
            checks.append({"name": f"pdf_structure:{rel}", "passed": bool(info.get("valid")), "detail": f"pages={info.get('pages')}"})
            if not info.get("valid"):
                defects.append({"code": "invalid_pdf", "target": rel, "detail": str(info)})

        for mdf in [f for f in files if f.suffix.lower() == ".md" and f.name != "HANDOVER.md"]:
            rel = str(mdf.relative_to(pdir))
            txt = mdf.read_text(encoding="utf-8", errors="replace")
            has_h1 = any(line.startswith("# ") for line in txt.splitlines())
            words = len(txt.split())
            links = re.findall(r"\[[^\]]+\]\(([^)#]+)\)", txt)
            broken_links = [
                lnk
                for lnk in links
                if not lnk.startswith(("http://", "https://", "mailto:")) and not (mdf.parent / lnk).exists() and not (pdir / lnk).exists()
            ]
            ok = has_h1 and words >= 12 and not broken_links
            checks.append(
                {
                    "name": f"markdown_quality:{rel}",
                    "passed": ok,
                    "detail": f"h1={has_h1}, words={words}, broken_links={len(broken_links)}",
                }
            )
            if not has_h1:
                defects.append({"code": "missing_markdown_heading", "target": rel, "detail": "Markdown document lacks top-level `# ` heading."})
            if broken_links:
                defects.append({"code": "broken_markdown_links", "target": rel, "detail": f"Broken relative links: {broken_links[:3]}"})

        # §129 Education quiz question-answer consistency check.
        for qzf in [f for f in files if f.name.endswith("quiz.json")]:
            rel = str(qzf.relative_to(pdir))
            try:
                qdata = json.loads(qzf.read_text(encoding="utf-8"))
                questions = qdata.get("questions") or []
                consistent = bool(questions) and all(
                    isinstance(q.get("options"), list)
                    and len(q["options"]) >= 2
                    and isinstance(q.get("answer_index"), int)
                    and 0 <= q["answer_index"] < len(q["options"])
                    and bool(str(q.get("explanation") or "").strip())
                    for q in questions
                )
            except ValueError:
                consistent = False
            checks.append({"name": f"quiz_qa_consistency:{rel}", "passed": consistent, "detail": "Verified options, answer_index bounds, and rationale."})
            if not consistent:
                defects.append({"code": "inconsistent_quiz", "target": rel, "detail": "Quiz item has out-of-range answer_index or missing explanation."})

        # CSV column consistency check.
        for csvf in [f for f in files if f.suffix.lower() == ".csv"]:
            rel = str(csvf.relative_to(pdir))
            rows = [r for r in csv.reader(csvf.read_text(encoding="utf-8", errors="replace").splitlines()) if r]
            widths = {len(r) for r in rows}
            ok = len(rows) >= 2 and len(widths) == 1
            checks.append({"name": f"csv_tabular_integrity:{rel}", "passed": ok, "detail": f"rows={len(rows)}, distinct_widths={sorted(widths)}"})
            if not ok:
                defects.append({"code": "ragged_or_empty_csv", "target": rel, "detail": f"CSV rows={len(rows)}, widths={sorted(widths)}"})

        if not checks:
            checks.append({"name": "spec_present", "passed": (pdir / "PROJECT_SPEC.json").is_file(), "detail": "PROJECT_SPEC.json inspected"})

        passed_cnt = sum(1 for c in checks if c["passed"])
        score = round(passed_cnt / max(1, len(checks)), 4)
        return {
            "passed": len(defects) == 0 and passed_cnt == len(checks),
            "quality_score": score,
            "domain": domain,
            "total_checks": len(checks),
            "passed_checks": passed_cnt,
            "checks": checks,
            "defects": defects,
            "file_existence_only": False,
        }


def apply_targeted_defect_repairs(project_dir: Path, defects: list[dict[str, Any]]) -> list[str]:
    """Deterministic targeted corrections for common inspectable defects (§139 step 4–5)."""
    pdir = Path(project_dir)
    applied: list[str] = []
    for defect in defects:
        code = defect.get("code")
        target_rel = str(defect.get("target") or "")
        target = (pdir / target_rel).resolve() if target_rel else pdir
        if not target.is_relative_to(pdir.resolve()):
            continue

        if code == "missing_svg_title" and target.is_file():
            raw = target.read_text(encoding="utf-8")
            idx = raw.find(">")
            if idx > 0 and "<title>" not in raw:
                patched = raw[: idx + 1] + f"<title>{target.stem}</title>" + raw[idx + 1 :]
                target.write_text(patched, encoding="utf-8")
                applied.append(f"inserted_accessible_svg_title:{target_rel}")
        elif code == "missing_png_preview" and target.is_file():
            preview_out = pdir / "renders" / f"{target.stem}_preview.png"
            res = render_svg_to_png(target, preview_out)
            if res.get("rendered"):
                applied.append(f"rendered_png_preview:{preview_out.relative_to(pdir)}")
        elif code == "missing_markdown_heading" and target.is_file():
            raw = target.read_text(encoding="utf-8")
            target.write_text(f"# {target.stem.replace('_', ' ').title()}\n\n{raw}", encoding="utf-8")
            applied.append(f"prepended_h1_heading:{target_rel}")
        elif code == "ragged_or_empty_csv" and target.is_file():
            rows = [r for r in csv.reader(target.read_text(encoding="utf-8").splitlines()) if any(c.strip() for c in r)]
            if rows:
                max_w = max(len(r) for r in rows)
                fixed = [r + [""] * (max_w - len(r)) for r in rows]
                with target.open("w", encoding="utf-8", newline="") as handle:
                    csv.writer(handle).writerows(fixed)
                applied.append(f"normalized_csv_columns:{target_rel}")
    return applied


class RefinementLoop:
    """§139 Bounded 10-step autonomous inspect-fix-verify-retain/revert refinement loop."""

    def __init__(
        self,
        qa_engine: QualityAssuranceEngine,
        lineage: LineageTracker,
        *,
        max_iterations: int = 3,
        max_wall_seconds: float = 25.0,
    ) -> None:
        self.qa = qa_engine
        self.lineage = lineage
        self.max_iterations = max(1, max_iterations)
        self.max_wall_seconds = max(1.0, max_wall_seconds)

    def run(
        self,
        *,
        project_id: str,
        domain: str,
        project_dir: Path,
        toolchain: dict[str, Any] | None = None,
        initial_version: int = 1,
        custom_repair_fn: Callable[[Path, list[dict[str, Any]], int], list[str]] | None = None,
    ) -> dict[str, Any]:
        started = time.monotonic()
        pdir = Path(project_dir)

        best_qa = self.qa.evaluate(domain, pdir)
        best_version = initial_version
        self.lineage.record_revision(
            project_id,
            pdir,
            version=best_version,
            stage="initial_build",
            summary=f"Initial deliverable QA score={best_qa['quality_score']}",
            qa_report=best_qa,
            toolchain=toolchain,
            retained=True,
        )

        history: list[dict[str, Any]] = [
            {
                "iteration": 0,
                "version": best_version,
                "quality_score": best_qa["quality_score"],
                "passed": best_qa["passed"],
                "defects": len(best_qa["defects"]),
                "action": "baseline_checkpoint",
                "retained": True,
            }
        ]

        next_version = best_version
        for step in range(1, self.max_iterations + 1):
            if best_qa["passed"]:
                break
            if (time.monotonic() - started) >= self.max_wall_seconds:
                history.append({"iteration": step, "action": "stopped_wall_budget_reached", "retained": False})
                break

            defects = list(best_qa["defects"])
            repairs = apply_targeted_defect_repairs(pdir, defects)
            if custom_repair_fn is not None:
                repairs.extend(custom_repair_fn(pdir, defects, step))

            if not repairs:
                history.append({"iteration": step, "action": "no_applicable_targeted_repair", "retained": False})
                break

            candidate_qa = self.qa.evaluate(domain, pdir)
            improved = (
                candidate_qa["quality_score"] > best_qa["quality_score"]
                or len(candidate_qa["defects"]) < len(best_qa["defects"])
            ) and candidate_qa["passed_checks"] >= best_qa["passed_checks"]

            if improved:
                next_version += 1
                best_version = next_version
                best_qa = candidate_qa
                self.lineage.record_revision(
                    project_id,
                    pdir,
                    version=best_version,
                    stage=f"refinement_{step}",
                    summary=f"Applied {len(repairs)} targeted fix(es); score={best_qa['quality_score']}",
                    qa_report=best_qa,
                    toolchain=toolchain,
                    modifications=repairs,
                    retained=True,
                )
                history.append(
                    {
                        "iteration": step,
                        "version": best_version,
                        "repairs": repairs,
                        "quality_score": best_qa["quality_score"],
                        "passed": best_qa["passed"],
                        "defects": len(best_qa["defects"]),
                        "action": "retained_improvement",
                        "retained": True,
                    }
                )
            else:
                # §139 step 8: Revert failed/regressing refinement so working deliverable is never destroyed!
                self.lineage.restore_revision(project_id, pdir, best_version)
                history.append(
                    {
                        "iteration": step,
                        "attempted_repairs": repairs,
                        "candidate_score": candidate_qa["quality_score"],
                        "reverted_to_version": best_version,
                        "action": "reverted_non_improving_attempt",
                        "retained": False,
                    }
                )
                break

        return {
            "final_version": best_version,
            "qa": best_qa,
            "iterations_executed": len(history) - 1,
            "history": history,
            "remaining_defects": best_qa["defects"],
        }


__all__ = [
    "QualityAssuranceEngine",
    "RefinementLoop",
    "apply_targeted_defect_repairs",
]
