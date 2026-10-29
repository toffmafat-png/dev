"""§116–§117 Universal intent-to-artifact engine, §145 natural-language commands, and §148 end-to-end capability test.

Coordinates capability discovery, toolchain selection, specialist team
assignment, domain studio generation, real quality assurance, checkpointed
refinement, asset indexing, lineage tracking, and handover packaging inside the
native Kali Linux NOVA X application.
"""
from __future__ import annotations

import asyncio
import csv
import hashlib
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nova.creation.factories import (
    build_3d_project,
    build_business_project,
    build_data_ml_or_simulation_project,
    build_database_project,
    build_design_code_bridge,
    build_education_project,
    build_engineering_project,
    build_game_project,
    build_integration_project,
    build_media_video_project,
    build_software_project,
    build_visual_design_project,
    build_web_mobile_project,
    build_writing_or_document_project,
)
from nova.creation.media_codecs import UniversalFormatConverter
from nova.creation.qa import QualityAssuranceEngine, RefinementLoop
from nova.creation.registry import (
    CapabilityDiscovery,
    TechnologyProposal,
    TechnologyRegistry,
    ToolchainOrchestrator,
)
from nova.creation.team import MultiModalCreationTeam
from nova.creation.workspace import CreativeWorkspaceManager
from nova.db import Database
from nova.observability import Redactor
from nova.plugins import PluginManager
from nova.resources import ResourceManager
from nova.workflows import WorkflowBlock, WorkflowEngine, WorkflowSpec

CAPABILITY_SUITE_VERSION = "nova-uce-v1"


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


_DOMAIN_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("plugin_capability", "nova_plugin_extension", re.compile(r"\b(plugin|extension|new capability for nova|nova skill)\b", re.I)),
    ("game", "playable_game", re.compile(r"\b(game|gameplay|playable|godot|sprite|level design|save[- ]state)\b", re.I)),
    ("3d", "parametric_3d_model", re.compile(r"\b(3d|mesh|stl|openscad|blender|printable|cad model|isometric model)\b", re.I)),
    ("engineering", "hardware_engineering_design", re.compile(r"\b(pcb|circuit|schematic|firmware|microcontroller|bom|bill of materials|electronics)\b", re.I)),
    ("media", "explainer_video_media", re.compile(r"\b(video|animation|explainer|storyboard|subtitle|podcast|narration|motion graphic|ffmpeg)\b", re.I)),
    ("visual_design", "editable_visual_asset", re.compile(r"\b(logo|brand identity|icon|svg|vector|poster|flyer|infographic|wireframe|design token|graphic)\b", re.I)),
    ("ml", "machine_learning_experiment", re.compile(r"\b(predictive model|machine[- ]learning|ml model|train a model|classifier|regression model|feature engineering)\b", re.I)),
    ("simulation", "computational_simulation", re.compile(r"\b(simulation|monte carlo|agent[- ]based|numerical experiment|sensitivity analysis|ode)\b", re.I)),
    ("database", "database_data_pipeline", re.compile(r"\b(database|schema|sql migration|etl|postgresql|relational model|deduplicat)\b", re.I)),
    ("education", "educational_course_pack", re.compile(r"\b(course|lesson plan|flashcard|quiz|study guide|curriculum|lecture note)\b", re.I)),
    ("business", "startup_product_package", re.compile(r"\b(business management|startup|pricing scenario|product requirement|market|landing[- ]page)\b", re.I)),
    ("web_mobile", "responsive_web_pwa", re.compile(r"\b(website|web app|pwa|progressive web|mobile app|frontend|responsive page)\b", re.I)),
    ("integration", "api_webhook_integration", re.compile(r"\b(webhook|api client|connector|mcp server|integration)\b", re.I)),
    ("conversion", "format_conversion_bundle", re.compile(r"\b(convert|transcode|file repair|fix encoding)\b", re.I)),
    ("writing", "creative_manuscript", re.compile(r"\b(novel|story|screenplay|dialogue|speech|fictional world)\b", re.I)),
    ("document", "office_publishing_bundle", re.compile(r"\b(docx|xlsx|pdf document|spreadsheet|technical manual|manuscript|report)\b", re.I)),
    ("software", "desktop_or_cli_application", re.compile(r"\b(desktop app|desktop utility|application|cli|command[- ]line|sdk|library|utility|tool)\b", re.I)),
)


class UniversalCreationEngine:
    """§116–§117 Central intent-to-artifact orchestrator integrated into NOVA X."""

    def __init__(
        self,
        *,
        db: Database,
        workspace_root: Path,
        resources: ResourceManager | None = None,
        redactor: Redactor | None = None,
        plugins: PluginManager | None = None,
        workflows: WorkflowEngine | None = None,
        permission_check: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
        provider_status_fn: Callable[[], dict[str, Any]] | None = None,
        integrations_fn: Callable[[], list[dict[str, Any]]] | None = None,
    ) -> None:
        self.db = db
        self.workspace_root = Path(workspace_root)
        self.resources = resources or ResourceManager(disk_path=str(self.workspace_root))
        self.redactor = redactor or Redactor()
        self.plugins = plugins
        self.workflows = workflows
        self.permission_check = permission_check

        self.registry = TechnologyRegistry(
            resources=self.resources,
            provider_status_fn=provider_status_fn,
            plugins_fn=(self.plugins.list_plugins if self.plugins else list),
            integrations_fn=integrations_fn,
        )
        self.discovery = CapabilityDiscovery(self.registry, self.resources)
        self.toolchains = ToolchainOrchestrator(self.registry)
        self.workspace = CreativeWorkspaceManager(
            db,
            self.workspace_root,
            redactor=self.redactor,
            permission_check=permission_check,
        )
        self.converter = UniversalFormatConverter()
        self.qa = QualityAssuranceEngine()
        self.refiner = RefinementLoop(self.qa, self.workspace.lineage)
        self.team = MultiModalCreationTeam()

    # ------------------------------------------------- §117 Step 1–3 Intent

    def recognize_intent(self, prompt: str) -> dict[str, Any]:
        """§117 Identify purpose, primary/secondary domains, project scope, and sensible defaults."""
        cleaned = prompt.strip()
        if not cleaned:
            raise ValueError("Creation request cannot be empty.")

        matched_domains: list[tuple[str, str]] = []
        for domain, art_type, pattern in _DOMAIN_PATTERNS:
            if pattern.search(cleaned):
                matched_domains.append((domain, art_type))

        if not matched_domains:
            # Dataset analysis cue fallback
            if re.search(r"\b(dataset|csv|analyze|statistic|chart|plot)\b", cleaned, re.I):
                matched_domains.append(("ml", "dataset_analysis_and_model"))
            else:
                matched_domains.append(("software", "desktop_or_cli_application"))

        primary_domain, primary_artifact = matched_domains[0]
        secondary_domains = [d for d, _ in matched_domains[1:] if d != primary_domain][:3]
        coordinated = len(secondary_domains) > 0 or bool(
            re.search(r"\b(complete|system|end[- ]to[- ]end|around it|and build|packaged product)\b", cleaned, re.I)
        )
        prototype_first = bool(re.search(r"\b(prototype|minimal|smallest working|mvp)\b", cleaned, re.I))
        editable_required = bool(re.search(r"\b(editable|vector|source|parametric|not just a preview)\b", cleaned, re.I)) or primary_domain in {
            "visual_design",
            "3d",
            "document",
            "software",
        }
        pref_lang = "c" if re.search(r"\b(in c\b|gcc|firmware)\b", cleaned, re.I) else ("javascript" if re.search(r"\b(node\.?js|javascript)\b", cleaned, re.I) else "python")
        unmet_external: list[str] = []
        pstate = self.registry._provider_status_fn()
        if re.search(r"\b(cinematic ai video|photorealistic neural video|sora|runway)\b", cleaned, re.I) and "video" not in (pstate.get("capabilities") or ()):
            unmet_external.append("Generative neural video provider is not configured; NOVA will assemble a verified procedural storyboard/video and report the missing external model.")

        words = [w for w in re.findall(r"[A-Za-z0-9]+", cleaned) if w.lower() not in {"build", "create", "make", "me", "a", "an", "the", "turn", "this", "into"}]
        inferred_name = " ".join(words[:5]).title() or "NOVA Deliverable"

        milestones = [
            "1. Capability & toolchain verification",
            f"2. Specification & {primary_domain} workspace initialization",
            "3. Initial deliverable synthesis",
            "4. Automated QA inspection & bounded refinement",
            *(["5. Handover packaging & asset indexing"] if not prototype_first else ["5. Prototype checkpoint"]),
        ]

        return {
            "inferred_name": inferred_name,
            "objective": cleaned,
            "domain": primary_domain,
            "artifact_type": primary_artifact,
            "secondary_domains": secondary_domains,
            "is_coordinated_project": coordinated,
            "prototype_first": prototype_first,
            "editable_required": editable_required,
            "preferred_language": pref_lang,
            "milestones": milestones,
            "unmet_external_capabilities": unmet_external,
        }

    # ------------------------------------------------- §117 Full 13-Step Engine

    async def create_from_intent(
        self,
        prompt: str,
        *,
        name: str = "",
        domain_override: str = "",
        options: dict[str, Any] | None = None,
        package: bool | None = None,
        run_refinement: bool = True,
    ) -> dict[str, Any]:
        opts = dict(options or {})
        intent = self.recognize_intent(prompt)
        domain = domain_override.strip() or intent["domain"]
        proj_name = name.strip() or intent["inferred_name"]
        should_package = (not intent["prototype_first"]) if package is None else bool(package)

        # Step 4: Capability, toolchain & resource check.
        toolchain = self.toolchains.select_toolchain(domain, preferred_language=str(opts.get("language") or intent["preferred_language"]))
        budget = self.resources.assess()

        # Step 5–6: Specification, acceptance criteria, and specialist team plan.
        team_plan = self.team.assemble_team(domain, is_coordinated_project=intent["is_coordinated_project"])
        acceptance_criteria = [
            "All generated source, asset, or document files pass structural/AST/header inspection (never file-existence alone).",
            "Domain-specific automated tests, mesh manifold checks, or media/data validations pass.",
            "Editable sources and explicit limitation/assumption disclosures are preserved in the workspace.",
        ]
        spec = {
            "intent": intent,
            "acceptance_criteria": acceptance_criteria,
            "milestones": intent["milestones"],
            "team": team_plan,
            "resource_pressure_at_start": budget.pressure,
            "dependencies": [t["id"] for t in toolchain["selected_tools"]],
        }
        project = self.workspace.create_project(
            name=proj_name,
            domain=domain,
            artifact_type=intent["artifact_type"],
            objective=prompt.strip(),
            spec=spec,
            toolchain=toolchain,
            license_name=str(opts.get("license") or "MIT"),
        )
        pdir = Path(project["project_dir"])

        # Step 7: Build initial deliverable (running secondary supporting views in parallel when coordinated & budget allows).
        build_result = await asyncio.to_thread(self._dispatch_factory, domain, pdir, proj_name, prompt.strip(), opts)

        secondary_domains = (
            list(opts.get("secondary_domains", []))
            if domain_override.strip()
            else [d for d in intent["secondary_domains"] if d != domain]
        )
        if secondary_domains and budget.max_background_workers >= 1 and not intent["prototype_first"]:
            sec_tasks = [
                asyncio.to_thread(self._build_secondary_companion, sec, pdir / "companion_artifacts" / sec, proj_name, prompt.strip())
                for sec in secondary_domains[:2]
            ]
            sec_outputs = await asyncio.gather(*sec_tasks)
            for sout in sec_outputs:
                build_result["primary_artifacts"].extend(sout.get("artifacts", []))
                build_result["limitations"].extend(sout.get("limitations", []))

        # Step 8–10: QA inspection & bounded refinement (§138–§139).
        if run_refinement:
            refinement = await asyncio.to_thread(
                self.refiner.run,
                project_id=project["id"],
                domain=domain,
                project_dir=pdir,
                toolchain=toolchain,
                initial_version=1,
            )
            qa_report = refinement["qa"]
            final_version = int(refinement["final_version"])
        else:
            qa_report = await asyncio.to_thread(self.qa.evaluate, domain, pdir)
            final_version = 1
            self.workspace.lineage.record_revision(
                project["id"],
                pdir,
                version=1,
                stage="initial_build",
                summary=f"Initial build QA score={qa_report['quality_score']}",
                qa_report=qa_report,
                toolchain=toolchain,
            )
            refinement = {"final_version": 1, "qa": qa_report, "iterations_executed": 0, "history": [], "remaining_defects": qa_report["defects"]}

        # Register visual/media/3D/document deliverables into §135 AssetLibrary.
        registered_assets: list[str] = []
        for rel in build_result.get("primary_artifacts", []):
            fp = pdir / rel
            if fp.is_file() and fp.suffix.lower() in {".svg", ".png", ".wav", ".avi", ".mp4", ".stl", ".obj", ".docx", ".xlsx", ".pdf"}:
                rec = self.workspace.assets.register_asset(
                    fp,
                    project_id=project["id"],
                    provenance="procedural",
                    license_name=project["license"],
                    tags=[domain, fp.suffix.lstrip(".")],
                )
                registered_assets.append(rec["id"])

        # §140 Final integration check.
        integration = self.team.validate_integration(pdir, team_plan, qa_report)

        limitations = list(
            dict.fromkeys(
                [
                    *intent["unmet_external_capabilities"],
                    *build_result.get("limitations", []),
                    *[f"Missing optional host tool: {m['name']} ({m['install_hint']})" for m in toolchain["missing_optional_tools"][:3]],
                ]
            )
        )

        project["current_version"] = final_version
        project["known_issues"] = limitations
        project["spec"] = {
            **project["spec"],
            "launch_instructions": build_result.get("launch_instructions", []),
            "build_instructions": build_result.get("build_instructions", []),
        }
        (pdir / "PROJECT_SPEC.json").write_text(__import__("json").dumps(project["spec"], indent=2) + "\n", encoding="utf-8")

        # Step 11: Optional handover packaging (§143).
        package_info: dict[str, Any] = {"packaged": False}
        status = "verified" if (qa_report["passed"] and integration["integrated_valid"]) else "completed_with_issues"
        if should_package and qa_report["passed"]:
            project["latest_report"] = {"primary_artifacts": build_result.get("primary_artifacts", []), "qa": qa_report}
            package_info = await asyncio.to_thread(self.workspace.packager.package, project)
            if package_info.get("packaged"):
                status = "packaged"

        # Step 12–13: Concise report & persistence.
        report = {
            "project_id": project["id"],
            "name": project["name"],
            "domain": domain,
            "artifact_type": intent["artifact_type"],
            "status": status,
            "project_dir": str(pdir),
            "version": final_version,
            "primary_artifacts": build_result.get("primary_artifacts", []),
            "qa": qa_report,
            "refinement": refinement,
            "integration": integration,
            "toolchain": toolchain,
            "package": package_info,
            "registered_asset_ids": registered_assets,
            "build_detail": {k: v for k, v in build_result.items() if k not in {"primary_artifacts", "limitations"}},
            "limitations": limitations,
            "created_at": _iso(),
        }
        project["status"] = status
        project["latest_report"] = report
        self.db.save_creation_project(project)
        self.db.save_creation_run(
            {
                "project_id": project["id"],
                "kind": f"create:{domain}",
                "status": status,
                "summary": f"{proj_name} ({domain}) -> {status} (QA {qa_report['quality_score']})",
                "payload": {"artifacts": report["primary_artifacts"], "qa_passed": qa_report["passed"]},
            }
        )
        return report

    def _dispatch_factory(
        self,
        domain: str,
        pdir: Path,
        name: str,
        objective: str,
        opts: dict[str, Any],
    ) -> dict[str, Any]:
        if domain == "software":
            return build_software_project(pdir, name=name, objective=objective, options=opts)
        if domain == "web_mobile":
            return build_web_mobile_project(pdir, name=name, objective=objective)
        if domain == "visual_design":
            if opts.get("bridge_mode"):
                return build_design_code_bridge(
                    pdir,
                    name=name,
                    reference_image=Path(opts["reference_image"]) if opts.get("reference_image") else None,
                    existing_html=Path(opts["existing_html"]) if opts.get("existing_html") else None,
                )
            return build_visual_design_project(
                pdir,
                name=name,
                objective=objective,
                seed=int(opts.get("seed", 42)),
                prefer_external_rasterizer=bool(opts.get("prefer_external_rasterizer", True)),
                forced_rasterizer_binary=opts.get("forced_rasterizer_binary"),
            )
        if domain == "media":
            return build_media_video_project(
                pdir,
                name=name,
                objective=objective,
                prefer_ffmpeg=bool(opts.get("prefer_ffmpeg", True)),
                forced_ffmpeg_binary=opts.get("forced_ffmpeg_binary"),
            )
        if domain == "3d":
            dims = tuple(opts.get("dimensions_mm") or (60.0, 40.0, 24.0))
            return build_3d_project(pdir, name=name, objective=objective, dimensions_mm=(float(dims[0]), float(dims[1]), float(dims[2])))
        if domain == "engineering":
            return build_engineering_project(pdir, name=name, objective=objective)
        if domain == "game":
            return build_game_project(pdir, name=name, objective=objective)
        if domain == "database":
            return build_database_project(pdir, name=name, objective=objective)
        if domain in {"ml", "simulation"}:
            supplied = Path(opts["dataset_path"]) if opts.get("dataset_path") else None
            return build_data_ml_or_simulation_project(
                pdir,
                domain=domain,
                name=name,
                objective=objective,
                supplied_csv=supplied,
                seed=int(opts.get("seed", 42)),
            )
        if domain in {"writing", "document"}:
            fictional = bool(re.search(r"\b(novel|story|fiction|screenplay|world)\b", objective, re.I))
            return build_writing_or_document_project(pdir, domain=domain, name=name, objective=objective, fictional=fictional)
        if domain == "education":
            return build_education_project(
                pdir,
                name=name,
                objective=objective,
                difficulty=str(opts.get("difficulty") or "intermediate"),
                lecture_notes=str(opts.get("lecture_notes") or ""),
            )
        if domain == "business":
            return build_business_project(pdir, name=name, objective=objective)
        if domain == "integration":
            return build_integration_project(pdir, name=name, objective=objective)
        if domain == "plugin_capability":
            return self._build_candidate_plugin_project(pdir, name=name, objective=objective)
        if domain == "conversion":
            src_csv = pdir / "inputs" / "sample.csv"
            src_csv.parent.mkdir(parents=True, exist_ok=True)
            src_csv.write_text("id,label\n1,alpha\n2,beta\n", encoding="utf-8")
            conv = self.converter.convert(src_csv, pdir / "converted" / "sample.json")
            return {
                "primary_artifacts": ["inputs/sample.csv", "converted/sample.json"],
                "conversion": conv,
                "launch_instructions": ["Inspect converted/sample.json."],
                "build_instructions": [],
                "limitations": conv.get("information_lost", []),
            }
        return build_software_project(pdir, name=name, objective=objective, options=opts)

    def _build_secondary_companion(self, sec_domain: str, target_dir: Path, name: str, objective: str) -> dict[str, Any]:
        target_dir.mkdir(parents=True, exist_ok=True)
        res = self._dispatch_factory(sec_domain, target_dir, f"{name} ({sec_domain})", objective, {})
        rel_prefix = f"companion_artifacts/{sec_domain}"
        return {
            "artifacts": [f"{rel_prefix}/{p}" for p in res.get("primary_artifacts", [])],
            "limitations": res.get("limitations", []),
        }

    def _build_candidate_plugin_project(self, pdir: Path, *, name: str, objective: str) -> dict[str, Any]:
        """§136, §147 & §148 Build and sandbox-evaluate a candidate NOVA extension for a missing workflow."""
        slug_name = re.sub(r"[^a-z0-9\-]+", "-", name.lower()).strip("-")[:32] or "markdown-toc-skill"
        if not slug_name[0].isalpha():
            slug_name = f"skill-{slug_name}"

        entrypoint_code = '''"""Sandboxed candidate NOVA X extension: deterministic Markdown TOC extractor."""
from __future__ import annotations

import json
import sys


def main() -> int:
    req = json.loads(sys.stdin.read() or "{}")
    args = req.get("arguments") or {}
    markdown = str(args.get("markdown") or "")
    headings = []
    for line in markdown.splitlines():
        s = line.strip()
        if s.startswith("#"):
            level = len(s) - len(s.lstrip("#"))
            title = s[level:].strip()
            if title:
                headings.append({"level": level, "title": title})
    print(json.dumps({"headings": headings, "count": len(headings)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
        sha = hashlib.sha256(entrypoint_code.encode("utf-8")).hexdigest()
        manifest = {
            "name": slug_name,
            "version": "0.1.0",
            "purpose": objective[:240] or "Extract structured table-of-contents headings from Markdown files.",
            "category": "document_processing",
            "entrypoint": "plugin_main.py",
            "operations": [
                {
                    "name": "extract_toc",
                    "description": "Extract heading hierarchy from Markdown text.",
                    "input_schema": {"type": "object", "required": ["markdown"], "properties": {"markdown": {"type": "string"}}},
                    "output_schema": {
                        "type": "object",
                        "required": ["headings", "count"],
                        "properties": {"headings": {"type": "array"}, "count": {"type": "integer"}},
                    },
                    "autonomy_class": "routine",
                }
            ],
            "required_permissions": ["workspace.read"],
            "filesystem_access": "none",
            "network_access": "none",
            "trust": {"publisher": "nova-creation-engine", "sha256": sha, "trusted": False},
        }
        test_script = f'''import json, subprocess, sys
from pathlib import Path

entry = Path({str((pdir / "candidate_plugin" / "plugin_main.py").resolve())!r})
proc = subprocess.run(
    [sys.executable, str(entry)],
    input=json.dumps({{"operation": "extract_toc", "arguments": {{"markdown": "# Intro\\n## Architecture\\nText"}}}}),
    capture_output=True,
    text=True,
    check=True,
)
out = json.loads(proc.stdout)
assert out["count"] == 2
assert out["headings"][0]["title"] == "Intro"
'''
        cand_dir = pdir / "candidate_plugin"
        cand_dir.mkdir(parents=True, exist_ok=True)
        (cand_dir / "plugin_main.py").write_text(entrypoint_code, encoding="utf-8")
        (cand_dir / "plugin.json").write_text(__import__("json").dumps(manifest, indent=2) + "\n", encoding="utf-8")
        (pdir / "tests" / "test_candidate_plugin.py").parent.mkdir(parents=True, exist_ok=True)
        (pdir / "tests" / "test_candidate_plugin.py").write_text(
            "import json, subprocess, sys\nfrom pathlib import Path\n\n"
            "def test_plugin_entrypoint() -> None:\n"
            "    root = Path(__file__).resolve().parent.parent\n"
            "    proc = subprocess.run([sys.executable, str(root / 'candidate_plugin' / 'plugin_main.py')], "
            "input=json.dumps({'operation': 'extract_toc', 'arguments': {'markdown': '# H1\\n## H2'}}), capture_output=True, text=True, check=True)\n"
            "    assert json.loads(proc.stdout)['count'] == 2\n",
            encoding="utf-8",
        )

        staging_result: dict[str, Any] = {"staged": False, "note": "PluginManager not attached"}
        if self.plugins is not None:
            staging_result = self.plugins.stage_candidate(manifest, entrypoint_code, test_code=test_script)
        (pdir / "evaluation" / "sandbox_staging.json").parent.mkdir(parents=True, exist_ok=True)
        (pdir / "evaluation" / "sandbox_staging.json").write_text(__import__("json").dumps(staging_result, indent=2) + "\n", encoding="utf-8")
        (pdir / "docs" / "CANDIDATE_PLUGIN.md").parent.mkdir(parents=True, exist_ok=True)
        (pdir / "docs" / "CANDIDATE_PLUGIN.md").write_text(
            f"# {name} — Candidate Extension\n\nStaged in isolation before registration (`auto_enabled=False`).\n",
            encoding="utf-8",
        )
        return {
            "primary_artifacts": ["candidate_plugin/plugin.json", "candidate_plugin/plugin_main.py", "evaluation/sandbox_staging.json", "tests/test_candidate_plugin.py"],
            "staging": staging_result,
            "launch_instructions": ["Promote via PluginManager.promote_candidate after operator review."],
            "build_instructions": ["pytest -q"],
            "limitations": ["Candidate plugin remains isolated and disabled until explicit operator approval (§92/§148)."],
        }

    # ------------------------------------ Continue / Package / Blueprint ops

    def _prepare_continuation_files(
        self,
        project_id: str,
        proj: dict[str, Any],
        pdir: Path,
        revs: list[dict[str, Any]],
        *,
        instruction: str,
        action: str,
    ) -> dict[str, Any]:
        if action == "resume_checkpoint" and revs:
            valid_revs = [r for r in revs if r.get("retained") and r.get("snapshot_dir") and Path(r["snapshot_dir"]).is_dir()]
            if valid_revs:
                latest_valid = valid_revs[-1]
                restored = self.workspace.lineage.restore_revision(project_id, pdir, int(latest_valid["version"]))
            else:
                restored = {"restored": False, "reason": "no_retained_snapshot"}
        else:
            restored = {"restored": False, "reason": "in_place_refinement"}

        if instruction.strip():
            notes_file = pdir / "docs" / "ITERATION_NOTES.md"
            notes_file.parent.mkdir(parents=True, exist_ok=True)
            prev = notes_file.read_text(encoding="utf-8") if notes_file.is_file() else f"# {proj['name']} Iteration Log\n"
            notes_file.write_text(prev + f"\n## Update ({_iso()})\n{instruction.strip()}\n", encoding="utf-8")
        return restored

    async def continue_project(self, project_id: str, *, instruction: str = "", action: str = "refine") -> dict[str, Any]:
        proj = self.db.get_creation_project(project_id)
        if proj is None:
            raise KeyError(f"Project '{project_id}' not found.")
        pdir = Path(proj["project_dir"])
        revs = self.db.list_creation_revisions(project_id)
        restored = await asyncio.to_thread(
            self._prepare_continuation_files,
            project_id,
            proj,
            pdir,
            revs,
            instruction=instruction,
            action=action,
        )

        next_v = int(proj.get("current_version") or 1) + 1
        qa_report = await asyncio.to_thread(self.qa.evaluate, proj["domain"], pdir)
        prev_score = float(revs[-1]["quality_score"]) if revs else 0.0
        if revs and not qa_report["passed"] and qa_report["quality_score"] < prev_score:
            # Revert regression automatically (§139/§145)!
            self.workspace.lineage.restore_revision(project_id, pdir, int(revs[-1]["version"]))
            return {
                "continued": False,
                "reverted_regression": True,
                "project_id": project_id,
                "retained_version": int(revs[-1]["version"]),
                "qa": qa_report,
            }

        self.workspace.lineage.record_revision(
            project_id,
            pdir,
            version=next_v,
            stage="continued_edit",
            summary=instruction.strip()[:200] or f"Continued from checkpoint to v{next_v}",
            qa_report=qa_report,
            toolchain=proj.get("toolchain"),
        )
        proj["current_version"] = next_v
        proj["status"] = "verified" if qa_report["passed"] else "in_progress"
        self.db.save_creation_project(proj)
        return {
            "continued": True,
            "reverted_regression": False,
            "checkpoint_restore": restored,
            "project_id": project_id,
            "version": next_v,
            "qa": qa_report,
        }

    async def package_project(self, project_id: str, *, archive_format: str = "tar.gz") -> dict[str, Any]:
        proj = self.db.get_creation_project(project_id)
        if proj is None:
            raise KeyError(f"Project '{project_id}' not found.")
        pkg = await asyncio.to_thread(self.workspace.packager.package, proj, archive_format=archive_format)
        if pkg.get("packaged"):
            proj["status"] = "packaged"
            self.db.save_creation_project(proj)
        return pkg

    # ------------------------------------ §145 Universal Assistant Commands

    async def resolve_command(
        self,
        command_text: str,
        *,
        project_id: str = "",
        source_path: str = "",
        target_path: str = "",
    ) -> dict[str, Any]:
        """§145 Resolve natural-language creation commands against real registries and workspaces."""
        text = command_text.strip()
        low = text.lower()

        if "find the best available tools" in low or "available tools for" in low:
            intent = self.recognize_intent(text)
            tc = self.toolchains.select_toolchain(intent["domain"])
            disc = self.discovery.discover()
            return {"command_kind": "discover_tools", "domain": intent["domain"], "toolchain": tc, "installed_count": len(disc["installed_applications"])}

        if "smallest working prototype" in low or "prototype first" in low:
            res = await self.create_from_intent(text, package=False)
            return {"command_kind": "build_prototype", "result": res}

        if "inspect the available files" in low or "what can be reused" in low:
            domain = self.recognize_intent(text)["domain"]
            reusable = self.workspace.find_reusable_components(domain)
            explorer = self.workspace.explore_project(project_id) if project_id else {}
            return {"command_kind": "inspect_reusable", "reusable": reusable, "explorer": explorer}

        if "convert" in low and source_path and target_path:
            conv = self.converter.convert(Path(source_path), Path(target_path))
            return {"command_kind": "convert_format", "conversion": conv}

        if "compare" in low and ("previous" in low or "version" in low) and project_id:
            diff = self.workspace.lineage.compare_revisions(project_id)
            return {"command_kind": "compare_revisions", "comparison": diff}

        if ("continue" in low and "checkpoint" in low) and project_id:
            cont = await self.continue_project(project_id, instruction=text, action="resume_checkpoint")
            return {"command_kind": "continue_from_checkpoint", "result": cont}

        if ("improve" in low or "without breaking" in low) and project_id:
            cont = await self.continue_project(project_id, instruction=text, action="refine")
            return {"command_kind": "improve_existing", "result": cont}

        if "package everything" in low and project_id:
            pkg = await self.package_project(project_id)
            return {"command_kind": "package_project", "package": pkg}

        if ("reusable skill" in low or "blueprint" in low) and project_id:
            proj = self.db.get_creation_project(project_id)
            if proj is None:
                raise KeyError(f"Project '{project_id}' not found.")
            bp = self.workspace.blueprints.create_from_project(proj)
            return {"command_kind": "promote_blueprint", "blueprint": bp}

        if "research the missing dependency" in low or "missing dependency" in low:
            intent = self.recognize_intent(text)
            plan = self.discovery.propose_setup_plan(intent["domain"])
            proposal = TechnologyProposal(
                id=f"proposed-{intent['domain']}",
                name=(plan["recommended_addition"] or {}).get("name", f"{intent['domain']}-helper"),
                kind="python_module",
                domains=(intent["domain"],),
                solves=text[:200],
            )
            eval_res = self.registry.evaluate_proposal(proposal)
            return {"command_kind": "research_dependency", "setup_plan": plan, "evaluation": eval_res.to_dict()}

        if "editable version" in low or "not just a preview" in low:
            res = await self.create_from_intent(text, package=False)
            return {"command_kind": "create_editable", "result": res}

        # Default: full intent-to-artifact creation ("Create a complete project..." / "Generate the first version, test it, and fix...")
        res = await self.create_from_intent(text, run_refinement=True)
        return {"command_kind": "create_complete_project", "result": res}

    # ------------------------------------ §148 Universal Creation Capability Test

    async def run_capability_suite(self) -> dict[str, Any]:
        """§148 Run all 8 end-to-end creation demonstrations and report truthful outcomes."""
        cases: list[dict[str, Any]] = []

        # 1. Software: desktop utility, test it, and package its source.
        sw = await self.create_from_intent(
            "Build a desktop utility task tracker, test it, and package its source.",
            name="Nova Desk Tracker",
            domain_override="software",
            package=True,
        )
        cases.append(
            {
                "id": "01_software_desktop_utility",
                "domain": "software",
                "genuinely_ran": True,
                "passed": sw["qa"]["passed"] and sw["package"].get("packaged", False),
                "files_produced": sw["primary_artifacts"] + ([sw["package"]["archive_path"]] if sw["package"].get("packaged") else []),
                "tools_used": [t["id"] for t in sw["toolchain"]["selected_tools"]],
                "limitations": sw["limitations"],
            }
        )

        # 2. Visual design: editable graphic asset and export a preview.
        vd = await self.create_from_intent(
            "Design a professional brand identity SVG logo and export a PNG preview.",
            name="Helios Vector Brand",
            domain_override="visual_design",
            package=True,
        )
        cases.append(
            {
                "id": "02_visual_design_editable_asset",
                "domain": "visual_design",
                "genuinely_ran": True,
                "passed": vd["qa"]["passed"] and "sources/brand_identity.svg" in vd["primary_artifacts"] and "renders/brand_identity.png" in vd["primary_artifacts"],
                "files_produced": vd["primary_artifacts"],
                "tools_used": [vd["build_detail"]["render_detail"]["tool_used"], *[t["id"] for t in vd["toolchain"]["selected_tools"]]],
                "limitations": vd["limitations"],
            }
        )

        # 3. Media: assemble a short video from available assets.
        md = await self.create_from_intent(
            "Turn this script into a short animated explainer video with audio and subtitles.",
            name="Nova Explainer Reel",
            domain_override="media",
            package=True,
        )
        vid_valid = bool(md["build_detail"]["video_inspection"].get("valid"))
        cases.append(
            {
                "id": "03_media_short_video_assembly",
                "domain": "media",
                "genuinely_ran": True,
                "passed": md["qa"]["passed"] and vid_valid,
                "files_produced": md["primary_artifacts"],
                "tools_used": [md["build_detail"]["assembly_detail"]["tool_used"]],
                "limitations": md["limitations"],
            }
        )

        # 4. Data: analyze a supplied dataset and produce a reproducible report + visualization.
        supplied_csv = self.workspace_root / "inputs_uce" / "thermal_telemetry.csv"
        supplied_csv.parent.mkdir(parents=True, exist_ok=True)
        with supplied_csv.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["batch", "load_pct", "temp_c"])
            for b in range(1, 25):
                writer.writerow([b, b * 4.0, round(31.5 + 0.42 * (b * 4.0), 3)])
        da = await self.create_from_intent(
            "Analyze the supplied dataset and build a reproducible report with visualization.",
            name="Thermal Telemetry Study",
            domain_override="ml",
            options={"dataset_path": str(supplied_csv)},
            package=True,
        )
        cases.append(
            {
                "id": "04_data_analysis_and_visualization",
                "domain": "ml",
                "genuinely_ran": True,
                "passed": da["qa"]["passed"] and da["build_detail"]["metrics"]["synthetic_dataset"] is False,
                "files_produced": da["primary_artifacts"],
                "tools_used": [t["id"] for t in da["toolchain"]["selected_tools"]],
                "limitations": da["limitations"],
            }
        )

        # 5. 3D: generate a parametric model and verify exported geometry.
        d3 = await self.create_from_intent(
            "Create a 3D parametric enclosure model and verify the exported STL and OBJ files.",
            name="Sensor Enclosure 3D",
            domain_override="3d",
            options={"dimensions_mm": (64.0, 44.0, 20.0)},
            package=True,
        )
        mesh_ok = bool(d3["build_detail"]["mesh_validation"].get("watertight_manifold"))
        cases.append(
            {
                "id": "05_3d_parametric_model_validation",
                "domain": "3d",
                "genuinely_ran": True,
                "passed": d3["qa"]["passed"] and mesh_ok,
                "files_produced": d3["primary_artifacts"],
                "tools_used": [t["id"] for t in d3["toolchain"]["selected_tools"]],
                "limitations": d3["limitations"],
            }
        )

        # 6. Automation: create and test a workflow carrying out an authorized multi-step task.
        wf_passed = False
        wf_limitations: list[str] = []
        wf_files: list[str] = []
        if self.workflows is not None:
            wf_spec = WorkflowSpec(
                workflow_id="uce-verified-workflow",
                name="Authorized Calculation & Verification Workflow",
                entry_block_id="trig",
                blocks=[
                    WorkflowBlock(block_id="trig", block_type="trigger", label="Start", next_blocks=["step_calc"]),
                    WorkflowBlock(
                        block_id="step_calc",
                        block_type="tool_call",
                        label="Calculate batch checksum",
                        config={"tool_name": "math.calculate", "arguments": {"expression": "16 * 4"}},
                        next_blocks=["step_verify"],
                    ),
                    WorkflowBlock(block_id="step_verify", block_type="verification", label="Verify result", next_blocks=["step_done"]),
                    WorkflowBlock(block_id="step_done", block_type="completion", label="Completed"),
                ],
            )
            saved_wf = self.workflows.save_workflow(wf_spec, activate=True)
            val = saved_wf["validation"]
            dry = await self.workflows.execute("uce-verified-workflow", dry_run=True)
            live = await self.workflows.execute("uce-verified-workflow", dry_run=False)
            wf_out = self.workspace_root / "inputs_uce" / "workflow_run.json"
            wf_out.write_text(__import__("json").dumps({"validation": val, "dry_run": dry, "live_run": live}, indent=2) + "\n", encoding="utf-8")
            wf_files.append(str(wf_out.relative_to(self.workspace_root)))
            wf_passed = bool(val.get("valid")) and dry.get("status") == "dry_run_ok" and live.get("status") == "completed"
        else:
            wf_limitations.append("WorkflowEngine was not attached to UniversalCreationEngine.")
        cases.append(
            {
                "id": "06_automation_authorized_workflow",
                "domain": "automation",
                "genuinely_ran": self.workflows is not None,
                "passed": wf_passed,
                "files_produced": wf_files,
                "tools_used": ["nova.workflows.WorkflowEngine", "math.calculate"],
                "limitations": wf_limitations,
            }
        )

        # 7. New capability: identify gap, evaluate dependency, stage & evaluate candidate extension in isolation.
        prop_eval = self.registry.evaluate_proposal(
            TechnologyProposal(
                id="markdown-toc-plugin",
                name="Markdown TOC Extractor Skill",
                kind="plugin",
                domains=("document", "plugin_capability"),
                solves="Extract heading hierarchy from Markdown documents as a reusable NOVA skill.",
                supported_formats=(".md", ".toc.json"),
                min_ram_mb=32,
                cpu_cost="low",
            )
        )
        nc = await self.create_from_intent(
            "Build a plugin that gives NOVA a Markdown TOC capability and evaluate it in isolation.",
            name="Markdown TOC Skill",
            domain_override="plugin_capability",
            package=False,
        )
        staging = nc["build_detail"]["staging"]
        sbx_available = self.plugins.sandbox.detect().available if self.plugins is not None else False
        nc_passed = nc["qa"]["passed"] and prop_eval.approved_for_proposal and (
            (staging.get("staged") and staging.get("passed_checks")) if sbx_available else bool(staging.get("staged"))
        )
        nc_lims = list(nc["limitations"])
        if not sbx_available:
            nc_lims.append("Kernel user-namespace sandbox unavailable on this host; candidate test script verified via pytest while sandbox staging reported refusal truthfully.")
        cases.append(
            {
                "id": "07_new_capability_isolated_extension",
                "domain": "plugin_capability",
                "genuinely_ran": True,
                "passed": bool(nc_passed),
                "files_produced": nc["primary_artifacts"],
                "tools_used": ["TechnologyRegistry", "PluginManager.stage_candidate"],
                "limitations": nc_lims,
            }
        )

        # 8. Recovery: simulate a failed tool and verify accurate failure reporting + fallback recovery.
        rec = await self.create_from_intent(
            "Assemble a short video when the primary encoder fails and recover via local fallback.",
            name="Fallback Recovery Reel",
            domain_override="media",
            options={"forced_ffmpeg_binary": "/nonexistent/broken-ffmpeg-binary"},
            package=False,
        )
        asm = rec["build_detail"]["assembly_detail"]
        failure_reported = bool(asm.get("primary_tool_failure")) and any("FFmpeg failed" in lim for lim in rec["limitations"])
        recovered_ok = bool(asm.get("fallback_used")) and bool(rec["build_detail"]["video_inspection"].get("valid"))
        cases.append(
            {
                "id": "08_tool_failure_reporting_and_recovery",
                "domain": "recovery",
                "genuinely_ran": True,
                "passed": failure_reported and recovered_ok and rec["qa"]["passed"],
                "files_produced": rec["primary_artifacts"],
                "tools_used": ["broken_ffmpeg_probe", asm.get("tool_used", "")],
                "primary_failure_recorded": asm.get("primary_tool_failure", ""),
                "limitations": rec["limitations"],
            }
        )

        passed_count = sum(1 for c in cases if c["passed"])
        summary = {
            "suite_version": CAPABILITY_SUITE_VERSION,
            "executed_at": _iso(),
            "total_cases": len(cases),
            "passed_cases": passed_count,
            "all_demonstrated_passed": passed_count == len(cases),
            "all_creation_domains_claimed_universal": False,
            "scope_honesty_note": (
                "Passing these 8 demonstrations verifies the exercised local pipelines and fallbacks only; "
                "capabilities requiring unconfigured cloud generative models or uninstalled CAD/DCC suites remain explicitly bounded (§148)."
            ),
            "cases": cases,
        }
        self.db.save_creation_run(
            {
                "kind": "capability_suite",
                "status": "passed" if passed_count == len(cases) else "partial",
                "summary": f"{passed_count}/{len(cases)} §148 demonstrations passed",
                "payload": summary,
            }
        )
        return summary

    def summary(self) -> dict[str, Any]:
        """Secret-free status snapshot for health, API, and native Qt studio surfaces."""
        techs = self.registry.list_technologies(refresh=False)
        installed_techs = [t["id"] for t in techs if t["installed"]]
        stats = self.db.creation_stats()
        return {
            "suite_version": CAPABILITY_SUITE_VERSION,
            "supported_domains": list(self.discovery.discover(refresh=False)["local_runnable_domains"]),
            "installed_technologies": installed_techs,
            "installed_technology_count": len(installed_techs),
            "total_registered_technologies": len(techs),
            "stats": stats,
            "silent_install_permitted": False,
        }


__all__ = [
    "CAPABILITY_SUITE_VERSION",
    "UniversalCreationEngine",
]
