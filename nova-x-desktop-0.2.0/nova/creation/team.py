"""§140 Multi-modal creation team orchestration and final integration validation.

Assigns domain-appropriate specialist roles with disjoint path ownership so
parallel or staged sub-agents never overwrite the same file, then runs an
explicit integration verification pass across combined outputs.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nova.creation.workspace import EXCLUDED_SNAPSHOT_NAMES


@dataclass(frozen=True)
class SpecialistAssignment:
    role_id: str
    title: str
    responsibility: str
    owned_paths: tuple[str, ...]
    expected_outputs: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "role_id": self.role_id,
            "title": self.title,
            "responsibility": self.responsibility,
            "owned_paths": list(self.owned_paths),
            "expected_outputs": list(self.expected_outputs),
        }


_SECRET_LEAK_RE = re.compile(r"(?:sk-[A-Za-z0-9]{20,}|tvly-[A-Za-z0-9\-]{16,}|ghp_[A-Za-z0-9]{24,})")


class MultiModalCreationTeam:
    """§140 Recruits specialist roles with non-overlapping workspaces and validates integrated deliverables."""

    def assemble_team(self, domain: str, *, is_coordinated_project: bool = True) -> dict[str, Any]:
        roles: list[SpecialistAssignment] = [
            SpecialistAssignment(
                role_id="architect",
                title="Lead Specification & Architecture Agent",
                responsibility="Define PROJECT_SPEC.json, acceptance criteria, and interface contracts.",
                owned_paths=("PROJECT_SPEC.json",),
                expected_outputs=("PROJECT_SPEC.json",),
            )
        ]

        if domain in {"software", "web_mobile", "integration"}:
            roles.extend(
                [
                    SpecialistAssignment(
                        role_id="developer",
                        title="Implementation Engineer",
                        responsibility="Implement runnable modules, CLI/UI entrypoints, and schemas.",
                        owned_paths=("src", "frontend", "backend", "schema", "config"),
                        expected_outputs=("src",),
                    ),
                    SpecialistAssignment(
                        role_id="qa_engineer",
                        title="Verification & Test Engineer",
                        responsibility="Create and execute automated unit and acceptance tests.",
                        owned_paths=("tests",),
                        expected_outputs=("tests",),
                    ),
                    SpecialistAssignment(
                        role_id="security_docs",
                        title="Security & Documentation Specialist",
                        responsibility="Audit secret placeholders, permissions, and author usage documentation.",
                        owned_paths=("docs", "README.md"),
                        expected_outputs=("README.md",),
                    ),
                ]
            )
        elif domain == "game":
            roles.extend(
                [
                    SpecialistAssignment(
                        role_id="game_designer",
                        title="Game Systems & Narrative Designer",
                        responsibility="Author game design spec, mechanics rules, levels, and branching dialogue.",
                        owned_paths=("design",),
                        expected_outputs=("design",),
                    ),
                    SpecialistAssignment(
                        role_id="gameplay_programmer",
                        title="Gameplay & Save-State Programmer",
                        responsibility="Implement core loop, movement, input controller, and save/load state.",
                        owned_paths=("game", "saves"),
                        expected_outputs=("game",),
                    ),
                    SpecialistAssignment(
                        role_id="art_audio_artist",
                        title="2D/Audio Asset Producer",
                        responsibility="Generate editable SVG/PNG sprites and PCM sound effects.",
                        owned_paths=("assets",),
                        expected_outputs=("assets",),
                    ),
                    SpecialistAssignment(
                        role_id="qa_packager",
                        title="Gameplay QA & Build Engineer",
                        responsibility="Verify scene load, rules, and save-state via automated tests.",
                        owned_paths=("tests", "builds"),
                        expected_outputs=("tests",),
                    ),
                ]
            )
        elif domain in {"ml", "simulation", "database"}:
            roles.extend(
                [
                    SpecialistAssignment(
                        role_id="data_engineer",
                        title="Dataset & Schema Engineer",
                        responsibility="Prepare validated datasets, schemas, and migrations.",
                        owned_paths=("data", "schema", "migrations", "etl"),
                        expected_outputs=("data",),
                    ),
                    SpecialistAssignment(
                        role_id="modeller",
                        title="Statistical / Simulation Modeller",
                        responsibility="Implement reproducible scripts, seed control, and evaluation metrics.",
                        owned_paths=("experiments", "models", "simulation", "scenarios", "evaluation"),
                        expected_outputs=(),
                    ),
                    SpecialistAssignment(
                        role_id="visualizer_writer",
                        title="Scientific Visualization & Report Author",
                        responsibility="Produce charts and methodology/limitation reports.",
                        owned_paths=("plots", "reports", "docs", "tests"),
                        expected_outputs=(),
                    ),
                ]
            )
        elif domain in {"media", "visual_design", "3d", "engineering"}:
            roles.extend(
                [
                    SpecialistAssignment(
                        role_id="source_author",
                        title="Parametric / Vector / Script Author",
                        responsibility="Create editable source scripts, storyboards, SVG vectors, or CAD definitions.",
                        owned_paths=("sources", "script", "storyboard", "parametric", "schematics_bom", "firmware"),
                        expected_outputs=(),
                    ),
                    SpecialistAssignment(
                        role_id="renderer_assembler",
                        title="Render & Media Assembly Specialist",
                        responsibility="Compile meshes, rasterize previews, synthesize audio/subtitles, and mux video.",
                        owned_paths=("renders", "palettes", "comparisons", "frames", "audio", "subtitles", "meshes", "previews"),
                        expected_outputs=(),
                    ),
                    SpecialistAssignment(
                        role_id="inspector",
                        title="Geometry / Media QA Specialist",
                        responsibility="Validate dimensions, manifold watertightness, container headers, and safety notes.",
                        owned_paths=("validation", "calculations", "docs"),
                        expected_outputs=(),
                    ),
                ]
            )
        else:
            roles.extend(
                [
                    SpecialistAssignment(
                        role_id="content_author",
                        title="Domain Author & Curriculum/Product Strategist",
                        responsibility="Produce structured manuscripts, curricula, specifications, and models.",
                        owned_paths=("manuscripts", "outlines", "style_guide", "curriculum", "quizzes", "exercises", "specs", "financials", "sources", "inputs", "candidate_plugin"),
                        expected_outputs=(),
                    ),
                    SpecialistAssignment(
                        role_id="publisher_verifier",
                        title="Publishing, Export & Consistency Verifier",
                        responsibility="Generate DOCX/PDF/XLSX/HTML exports and run consistency checks.",
                        owned_paths=("exports", "slides", "references", "prototype", "schema", "templates", "checks", "repaired", "converted", "reports", "tests", "evaluation", "docs"),
                        expected_outputs=(),
                    ),
                ]
            )

        roles.append(
            SpecialistAssignment(
                role_id="integrator",
                title="Final Integration & Handover Validator",
                responsibility="Verify cross-component compatibility, zero ownership conflicts, and handover readiness.",
                owned_paths=("HANDOVER.md", "HANDOVER_MANIFEST.json", "dist_handover"),
                expected_outputs=(),
            )
        )

        conflicts = self.detect_scope_conflicts(roles)
        return {
            "domain": domain,
            "coordinated": is_coordinated_project,
            "roles": [r.to_dict() for r in roles],
            "scope_conflicts": conflicts,
            "disjoint_ownership_verified": len(conflicts) == 0,
        }

    @staticmethod
    def detect_scope_conflicts(roles: list[SpecialistAssignment]) -> list[str]:
        owners: dict[str, str] = {}
        conflicts: list[str] = []
        for role in roles:
            for path in role.owned_paths:
                norm = path.strip("/")
                if norm in owners and owners[norm] != role.role_id:
                    conflicts.append(f"path '{norm}' claimed by both '{owners[norm]}' and '{role.role_id}'")
                else:
                    owners[norm] = role.role_id
        return conflicts

    def validate_integration(
        self,
        project_dir: Path,
        team_plan: dict[str, Any],
        qa_report: dict[str, Any],
    ) -> dict[str, Any]:
        """§140 Final integration agent check across separately generated project components."""
        pdir = Path(project_dir)
        issues: list[str] = []
        if not team_plan.get("disjoint_ownership_verified", False):
            issues.extend(team_plan.get("scope_conflicts") or ["scope conflict"])

        if not (pdir / "PROJECT_SPEC.json").is_file():
            issues.append("missing PROJECT_SPEC.json contract")

        # Scan text files for accidental secret leakage or unresolved merge conflict markers.
        for fp in sorted(pdir.rglob("*")):
            if not fp.is_file():
                continue
            if any(part in EXCLUDED_SNAPSHOT_NAMES for part in fp.relative_to(pdir).parts):
                continue
            if fp.stat().st_size > 256_000:
                continue
            try:
                txt = fp.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            rel = str(fp.relative_to(pdir))
            if "<<<<<<<" in txt and ">>>>>>>" in txt:
                issues.append(f"unresolved conflict marker in {rel}")
            if _SECRET_LEAK_RE.search(txt):
                issues.append(f"potential live credential pattern detected in {rel}")

        if not qa_report.get("passed", False):
            issues.append(f"QA checks reported {len(qa_report.get('defects') or [])} unresolved defect(s)")

        return {
            "integrated_valid": len(issues) == 0,
            "roles_coordinated": len(team_plan.get("roles") or []),
            "issues": issues,
            "qa_score": qa_report.get("quality_score", 0.0),
        }


__all__ = [
    "MultiModalCreationTeam",
    "SpecialistAssignment",
]
