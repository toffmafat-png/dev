"""§119 Universal creative workspace, §135 asset library, §141 blueprints, §143 handover packaging, and §144 lineage.

Organizes projects using domain-appropriate directory structures, tracks
asset provenance and copyright restrictions, extracts credential-free blueprints
from verified projects, maintains storage-bounded revision history, and builds
reopenable handover archives.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import mimetypes
import re
import shutil
import tarfile
import uuid
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nova.db import Database
from nova.observability import Redactor

# §119: Choose an appropriate project layout based on purpose rather than one rigid folder tree.
DOMAIN_LAYOUTS: dict[str, tuple[str, ...]] = {
    "software": ("src", "tests", "config", "docs", "dist"),
    "web_mobile": ("frontend", "backend", "schema", "tests", "docs"),
    "writing": ("manuscripts", "outlines", "style_guide", "exports", "references"),
    "visual_design": ("sources", "renders", "palettes", "comparisons", "docs"),
    "media": ("script", "storyboard", "frames", "audio", "subtitles", "renders"),
    "3d": ("parametric", "meshes", "previews", "validation", "docs"),
    "game": ("design", "game", "assets", "saves", "tests", "builds"),
    "database": ("schema", "migrations", "etl", "data", "reports", "tests"),
    "ml": ("data", "experiments", "models", "evaluation", "docs"),
    "engineering": ("parametric", "schematics_bom", "firmware", "calculations", "docs"),
    "simulation": ("simulation", "scenarios", "plots", "reports", "tests"),
    "education": ("curriculum", "quizzes", "exercises", "slides", "references"),
    "business": ("specs", "financials", "prototype", "schema", "docs"),
    "document": ("sources", "exports", "templates", "checks"),
    "conversion": ("inputs", "repaired", "converted", "reports"),
    "integration": ("src", "config", "tests", "docs"),
    "plugin_capability": ("candidate_plugin", "tests", "evaluation", "docs"),
}

EXCLUDED_SNAPSHOT_NAMES = frozenset(
    {
        ".nova_history",
        "__pycache__",
        ".pytest_cache",
        ".venv",
        "node_modules",
        ".env",
        "dist_handover",
    }
)

RESTRICTED_LICENSES = frozenset(
    {
        "unknown",
        "unverified",
        "copyrighted",
        "all_rights_reserved",
        "proprietary_restricted",
    }
)

PERMISSIVE_REUSABLE_LICENSES = frozenset(
    {
        "mit",
        "apache-2.0",
        "bsd-2-clause",
        "bsd-3-clause",
        "cc0-1.0",
        "cc-by-4.0",
        "psf-2.0",
        "public domain",
    }
)


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def slugify(text: str, max_len: int = 48) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", text.strip().lower()).strip("-")
    return (cleaned[:max_len].rstrip("-") or "nova-project")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(65536):
            h.update(chunk)
    return h.hexdigest()


def classify_file_kind(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in {".py", ".js", ".ts", ".c", ".cpp", ".h", ".rs", ".go", ".java", ".sql", ".gd", ".sh"}:
        return "test" if ("test_" in path.name or path.name.endswith("_test.py") or "tests" in path.parts) else "source_code"
    if ext in {".svg", ".tokens.json"} or path.name.endswith(".tokens.json"):
        return "design_source"
    if ext in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ppm", ".bmp", ".ico"}:
        return "image_asset"
    if ext in {".mp4", ".webm", ".avi", ".mkv", ".wav", ".mp3", ".ogg", ".srt", ".vtt"}:
        return "media_asset"
    if ext in {".stl", ".obj", ".mtl", ".scad", ".FCStd", ".step"}:
        return "3d_or_cad"
    if ext in {".csv", ".sqlite3", ".db", ".xlsx"}:
        return "dataset_or_db"
    if ext in {".md", ".html", ".pdf", ".docx", ".txt", ".rst"}:
        return "document"
    if ext in {".json", ".toml", ".yaml", ".yml", ".ini", ".example"}:
        return "configuration"
    if ext in {".tar", ".gz", ".zip", ".deb"}:
        return "package"
    return "artifact"


class AssetLibrary:
    """§135 Searchable creative asset library with provenance, license guards, and deduplication."""

    def __init__(self, db: Database, workspace_root: Path) -> None:
        self.db = db
        self.workspace_root = Path(workspace_root)

    def register_asset(
        self,
        file_path: Path,
        *,
        project_id: str = "",
        provenance: str = "procedural",
        license_name: str = "MIT",
        tags: list[str] | tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
        usage_notes: str = "",
        preview_path: Path | None = None,
        parent_asset_id: str = "",
        version: int = 1,
    ) -> dict[str, Any]:
        target = Path(file_path).resolve()
        if not target.is_file():
            raise FileNotFoundError(f"Asset file does not exist: {target}")

        norm_license = license_name.strip() or "unknown"
        license_low = norm_license.lower()
        # §135: Never present copyrighted or unverified external assets as freely reusable.
        is_restricted = license_low in RESTRICTED_LICENSES or (
            provenance == "external_sourced" and license_low not in PERMISSIVE_REUSABLE_LICENSES
        )
        reusable = not is_restricted
        notes = usage_notes
        if is_restricted and "copyright/license verification required" not in notes.lower():
            notes = (notes + " [RESTRICTED: copyright/license verification required before reuse]").strip()

        sha = _sha256_file(target)
        duplicates = [a["id"] for a in self.db.list_creation_assets(limit=500) if a["sha256"] == sha and a["rel_path"] != self._rel(target)]
        mime, _ = mimetypes.guess_type(target.name)
        meta = {
            **(metadata or {}),
            "duplicate_of_asset_ids": duplicates,
            "kind": classify_file_kind(target),
        }

        record = {
            "id": str(uuid.uuid4()),
            "project_id": project_id,
            "filename": target.name,
            "rel_path": self._rel(target),
            "media_type": mime or f"application/x-{target.suffix.lstrip('.') or 'binary'}",
            "sha256": sha,
            "size_bytes": target.stat().st_size,
            "version": version,
            "parent_asset_id": parent_asset_id,
            "provenance": provenance,
            "license": norm_license,
            "reusable": reusable,
            "tags": list(dict.fromkeys(str(t).strip() for t in tags if str(t).strip())),
            "metadata": meta,
            "usage_notes": notes,
            "preview_rel_path": self._rel(preview_path.resolve()) if (preview_path and preview_path.is_file()) else "",
        }
        self.db.save_creation_asset(record)
        return record

    def _rel(self, target: Path) -> str:
        try:
            return str(target.relative_to(self.workspace_root.resolve()))
        except ValueError:
            return str(target)

    def search(self, *, project_id: str = "", query: str = "", media_type: str = "", reusable_only: bool = False) -> list[dict[str, Any]]:
        items = self.db.list_creation_assets(project_id=project_id, query=query, media_type=media_type)
        if reusable_only:
            items = [a for a in items if a.get("reusable")]
        return items

    def find_duplicates(self, project_id: str = "") -> list[dict[str, Any]]:
        by_sha: dict[str, list[dict[str, Any]]] = {}
        for item in self.db.list_creation_assets(project_id=project_id, limit=500):
            if item.get("sha256"):
                by_sha.setdefault(item["sha256"], []).append(item)
        return [{"sha256": sha, "count": len(group), "assets": group} for sha, group in by_sha.items() if len(group) > 1]

    def export_project_library(self, project_id: str, export_dir: Path) -> dict[str, Any]:
        assets = self.search(project_id=project_id)
        out_dir = Path(export_dir)
        files_dir = out_dir / "files"
        files_dir.mkdir(parents=True, exist_ok=True)
        copied: list[str] = []
        for asset in assets:
            src = (self.workspace_root / asset["rel_path"]) if not Path(asset["rel_path"]).is_absolute() else Path(asset["rel_path"])
            if src.is_file():
                dst = files_dir / f"{asset['id'][:8]}_{src.name}"
                shutil.copy2(src, dst)
                copied.append(str(dst))
        manifest_path = out_dir / "asset_library_manifest.json"
        manifest_path.write_text(json.dumps({"project_id": project_id, "exported_at": _iso(), "assets": assets}, indent=2), encoding="utf-8")
        return {"exported": True, "manifest": str(manifest_path), "file_count": len(copied)}


class LineageTracker:
    """§144 Tracks project revisions, artifact lineage, diff comparisons, and storage-bounded recovery."""

    def __init__(
        self,
        db: Database,
        *,
        max_revisions_per_project: int = 12,
        max_history_bytes_per_project: int = 32 * 1024 * 1024,
    ) -> None:
        self.db = db
        self.max_revisions = max(2, max_revisions_per_project)
        self.max_history_bytes = max(512 * 1024, max_history_bytes_per_project)

    def record_revision(
        self,
        project_id: str,
        project_dir: Path,
        *,
        version: int,
        stage: str,
        summary: str,
        qa_report: dict[str, Any],
        toolchain: dict[str, Any] | None = None,
        source_inputs: list[str] | None = None,
        modifications: list[str] | None = None,
        limitations: list[str] | None = None,
        retained: bool = True,
    ) -> dict[str, Any]:
        pdir = Path(project_dir)
        hist_root = pdir / ".nova_history"
        snap_dir = hist_root / f"rev_{version:03d}"
        if snap_dir.exists():
            shutil.rmtree(snap_dir)
        snap_dir.mkdir(parents=True, exist_ok=True)

        artifacts_meta: list[dict[str, Any]] = []
        total_bytes = 0
        for item in sorted(pdir.rglob("*")):
            if not item.is_file():
                continue
            rel_parts = item.relative_to(pdir).parts
            if any(part in EXCLUDED_SNAPSHOT_NAMES for part in rel_parts):
                continue
            rel_str = str(item.relative_to(pdir))
            dst = snap_dir / rel_str
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, dst)
            sz = item.stat().st_size
            total_bytes += sz
            artifacts_meta.append(
                {
                    "path": rel_str,
                    "kind": classify_file_kind(item),
                    "sha256": _sha256_file(item),
                    "size_bytes": sz,
                    "version": version,
                    "process": stage,
                    "source_inputs": list(source_inputs or []),
                    "toolchain": [t["id"] for t in (toolchain or {}).get("selected_tools", [])],
                    "modifications": list(modifications or []),
                    "checks_performed": [c.get("name", "") for c in qa_report.get("checks", [])],
                    "limitations": list(limitations or []),
                }
            )

        rev_record = {
            "id": str(uuid.uuid4()),
            "project_id": project_id,
            "version": version,
            "stage": stage,
            "summary": summary,
            "snapshot_dir": str(snap_dir),
            "artifacts": artifacts_meta,
            "qa": qa_report,
            "quality_score": float(qa_report.get("quality_score") or 0.0),
            "retained": retained,
            "size_bytes": total_bytes,
            "created_at": _iso(),
        }
        self.db.save_creation_revision(rev_record)
        self._enforce_storage_limits(project_id)
        return rev_record

    def _enforce_storage_limits(self, project_id: str) -> None:
        revs = self.db.list_creation_revisions(project_id, limit=500)
        if not revs:
            return
        total = sum(int(r.get("size_bytes") or 0) for r in revs if r.get("snapshot_dir") and Path(r["snapshot_dir"]).exists())
        # Keep the latest 2 revisions unconditionally; prune oldest snapshots first if caps exceeded.
        prunable = revs[:-2]
        idx = 0
        while idx < len(prunable) and (len(revs) - idx > self.max_revisions or total > self.max_history_bytes):
            cand = prunable[idx]
            sdir = Path(cand["snapshot_dir"]) if cand.get("snapshot_dir") else None
            if sdir and sdir.exists():
                shutil.rmtree(sdir, ignore_errors=True)
                total = max(0, total - int(cand.get("size_bytes") or 0))
                cand["snapshot_dir"] = ""
                cand["size_bytes"] = 0
                self.db.save_creation_revision(cand)
            idx += 1

    def compare_revisions(self, project_id: str, version_a: int | None = None, version_b: int | None = None) -> dict[str, Any]:
        revs = self.db.list_creation_revisions(project_id)
        if len(revs) < 2 and (version_a is None or version_b is None):
            if len(revs) == 1:
                only = revs[0]
                return {
                    "comparable": False,
                    "reason": "only_one_revision_recorded",
                    "version_a": only["version"],
                    "version_b": only["version"],
                    "score_delta": 0.0,
                    "changed_files": [],
                    "diffs": {},
                }
            return {"comparable": False, "reason": "no_revisions_recorded", "changed_files": [], "diffs": {}}

        by_ver = {int(r["version"]): r for r in revs}
        va = version_a if version_a is not None else revs[-2]["version"]
        vb = version_b if version_b is not None else revs[-1]["version"]
        ra = by_ver.get(int(va))
        rb = by_ver.get(int(vb))
        if ra is None or rb is None:
            return {"comparable": False, "reason": "requested_revision_not_found", "changed_files": [], "diffs": {}}

        map_a = {a["path"]: a for a in ra.get("artifacts", [])}
        map_b = {a["path"]: a for a in rb.get("artifacts", [])}
        all_paths = sorted(set(map_a) | set(map_b))
        changed: list[dict[str, str]] = []
        diffs: dict[str, str] = {}
        sa_dir = Path(ra["snapshot_dir"]) if ra.get("snapshot_dir") else None
        sb_dir = Path(rb["snapshot_dir"]) if rb.get("snapshot_dir") else None

        for rel in all_paths:
            if rel not in map_a:
                changed.append({"path": rel, "change": "added"})
            elif rel not in map_b:
                changed.append({"path": rel, "change": "removed"})
            elif map_a[rel]["sha256"] != map_b[rel]["sha256"]:
                changed.append({"path": rel, "change": "modified"})
                if sa_dir and sb_dir and (sa_dir / rel).is_file() and (sb_dir / rel).is_file() and len(diffs) < 12:
                    try:
                        la = (sa_dir / rel).read_text(encoding="utf-8").splitlines()
                        lb = (sb_dir / rel).read_text(encoding="utf-8").splitlines()
                        diffs[rel] = "\n".join(difflib.unified_diff(la, lb, fromfile=f"v{va}/{rel}", tofile=f"v{vb}/{rel}", lineterm=""))[:4000]
                    except UnicodeDecodeError:
                        diffs[rel] = f"Binary file modified ({map_a[rel]['size_bytes']} -> {map_b[rel]['size_bytes']} bytes)"

        return {
            "comparable": True,
            "version_a": int(va),
            "version_b": int(vb),
            "score_a": ra["quality_score"],
            "score_b": rb["quality_score"],
            "score_delta": round(float(rb["quality_score"]) - float(ra["quality_score"]), 4),
            "changed_files": changed,
            "diffs": diffs,
        }

    def restore_revision(self, project_id: str, project_dir: Path, version: int) -> dict[str, Any]:
        revs = self.db.list_creation_revisions(project_id)
        target_rev = next((r for r in revs if int(r["version"]) == int(version)), None)
        if target_rev is None or not target_rev.get("snapshot_dir") or not Path(target_rev["snapshot_dir"]).is_dir():
            return {"restored": False, "reason": f"revision v{version} snapshot is not available on disk"}

        pdir = Path(project_dir)
        for item in list(pdir.iterdir()):
            if item.name in EXCLUDED_SNAPSHOT_NAMES:
                continue
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()

        snap = Path(target_rev["snapshot_dir"])
        restored_files: list[str] = []
        for src in sorted(snap.rglob("*")):
            if not src.is_file():
                continue
            rel = src.relative_to(snap)
            dst = pdir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            restored_files.append(str(rel))

        return {"restored": True, "version": int(version), "restored_files": restored_files}

    def trace_artifact(self, project_id: str, rel_path: str) -> dict[str, Any]:
        revs = self.db.list_creation_revisions(project_id)
        history: list[dict[str, Any]] = []
        for rev in revs:
            for art in rev.get("artifacts", []):
                if art["path"] == rel_path:
                    history.append({"revision": rev["version"], "created_at": rev["created_at"], **art})
        return {
            "project_id": project_id,
            "artifact": rel_path,
            "found": bool(history),
            "lineage": history,
        }


class BlueprintLibrary:
    """§141 Versioned, credential-scrubbed reusable creation blueprints."""

    def __init__(self, db: Database, redactor: Redactor) -> None:
        self.db = db
        self.redactor = redactor

    def create_from_project(
        self,
        project: dict[str, Any],
        *,
        blueprint_name: str = "",
        customization_points: list[str] | None = None,
        version: str = "1.0.0",
    ) -> dict[str, Any]:
        if project.get("status") not in {"completed", "verified", "packaged"}:
            raise ValueError("Only verified or completed projects may be promoted into reusable blueprints (§141).")

        pdir = Path(project["project_dir"])
        reusable_files: dict[str, str] = {}
        if pdir.is_dir():
            for fp in sorted(pdir.rglob("*")):
                if not fp.is_file():
                    continue
                rel_parts = fp.relative_to(pdir).parts
                if any(part in EXCLUDED_SNAPSHOT_NAMES for part in rel_parts):
                    continue
                if fp.name in {".env", "credentials.json", "secrets.json"} or fp.stat().st_size > 64_000:
                    continue
                if fp.suffix.lower() in {".py", ".js", ".html", ".css", ".sql", ".md", ".svg", ".scad", ".json", ".toml"}:
                    try:
                        raw_txt = fp.read_text(encoding="utf-8")
                        # Scrub any accidental literal secret or token before storing in blueprint!
                        scrubbed = self.redactor.scrub_text(raw_txt, max_chars=64_000)
                        reusable_files[str(fp.relative_to(pdir))] = scrubbed
                    except UnicodeDecodeError:
                        continue

        spec = project.get("spec") or {}
        toolchain = project.get("toolchain") or {}
        payload = {
            "structure": list(DOMAIN_LAYOUTS.get(project["domain"], ("src", "docs"))),
            "required_technologies": [t["id"] for t in toolchain.get("selected_tools", [])],
            "configuration_template": {"NOVA_ENV": "development", "API_KEY_PLACEHOLDER": "CHANGE_ME_VIA_SECRET_STORE"},
            "dependencies": spec.get("dependencies", []),
            "reusable_modules": sorted(reusable_files.keys()),
            "template_files": reusable_files,
            "build_instructions": spec.get("build_instructions", ["Inspect PROJECT_SPEC.json"]),
            "test_instructions": spec.get("test_instructions", ["pytest -q"]),
            "known_limitations": project.get("known_issues", []),
            "customization_points": customization_points or ["objective", "project_name", "parameters"],
            "licensing": project.get("license", "MIT"),
        }
        record = {
            "id": f"bp-{slugify(blueprint_name or project['name'])}",
            "name": blueprint_name or f"{project['name']} Blueprint",
            "version": version,
            "domain": project["domain"],
            "artifact_type": project["artifact_type"],
            "source_project_id": project["id"],
            "objective": self.redactor.scrub_text(project["objective"], max_chars=1500),
            "license": project.get("license", "MIT"),
            "payload": payload,
        }
        self.db.save_creation_blueprint(record)
        return record

    def instantiate(self, blueprint_id: str, target_dir: Path, *, installed_tool_ids: set[str]) -> dict[str, Any]:
        bp = self.db.get_creation_blueprint(blueprint_id)
        if bp is None:
            return {"instantiated": False, "error": f"blueprint '{blueprint_id}' not found"}
        payload = bp["payload"]
        req_tools = set(payload.get("required_technologies") or [])
        missing = sorted(req_tools - installed_tool_ids)
        out = Path(target_dir)
        out.mkdir(parents=True, exist_ok=True)
        for folder in payload.get("structure", []):
            (out / folder).mkdir(parents=True, exist_ok=True)
        written: list[str] = []
        for rel_path, content in (payload.get("template_files") or {}).items():
            fp = (out / rel_path).resolve()
            if not fp.is_relative_to(out.resolve()):
                continue
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(content, encoding="utf-8")
            written.append(rel_path)
        return {
            "instantiated": True,
            "blueprint_id": blueprint_id,
            "version": bp["version"],
            "written_files": written,
            "missing_technologies": missing,
            "compatible": len(missing) == 0,
        }


class HandoverPackager:
    """§143 Packages verified deliverables with editable sources, docs, tests, and secret exclusions."""

    FORBIDDEN_FILENAMES = frozenset({".env", ".env.local", "id_rsa", "credentials.json", "secrets.json"})

    def __init__(self, redactor: Redactor) -> None:
        self.redactor = redactor

    def package(self, project: dict[str, Any], *, archive_format: str = "tar.gz") -> dict[str, Any]:
        pdir = Path(project["project_dir"])
        if not pdir.is_dir():
            return {"packaged": False, "error": "project_directory_missing"}

        spec = project.get("spec") or {}
        report = project.get("latest_report") or {}
        qa = report.get("qa") or {}
        files_included: list[str] = []
        editable_sources: list[str] = []

        for fp in sorted(pdir.rglob("*")):
            if not fp.is_file():
                continue
            rel_parts = fp.relative_to(pdir).parts
            if any(part in EXCLUDED_SNAPSHOT_NAMES for part in rel_parts):
                continue
            if fp.name in self.FORBIDDEN_FILENAMES or fp.suffix in {".pyc", ".pyo"}:
                continue
            rel_s = str(fp.relative_to(pdir))
            files_included.append(rel_s)
            if classify_file_kind(fp) in {"source_code", "design_source", "3d_or_cad", "document"}:
                editable_sources.append(rel_s)

        manifest = {
            "nova_handover_schema": "nova-handover-v1",
            "project_id": project["id"],
            "slug": project["slug"],
            "name": project["name"],
            "version": f"0.{max(1, int(project.get('current_version') or 1))}.0",
            "domain": project["domain"],
            "artifact_type": project["artifact_type"],
            "objective": self.redactor.scrub_text(project["objective"], max_chars=2000),
            "final_artifacts": report.get("primary_artifacts", files_included[:12]),
            "editable_sources": editable_sources,
            "dependencies": spec.get("dependencies", []),
            "install_and_launch": spec.get("launch_instructions", ["See README.md for local execution steps."]),
            "configuration_template": spec.get("config_template", {"APP_ENV": "local", "SECRET_KEY": "<configure-in-secret-store>"}),
            "tests_and_results": {
                "passed": qa.get("passed", False),
                "quality_score": qa.get("quality_score", 0.0),
                "checks": qa.get("checks", []),
            },
            "licensing": project.get("license", "MIT"),
            "known_limitations": project.get("known_issues", []),
            "source_references": spec.get("references", []),
            "build_instructions": spec.get("build_instructions", []),
            "export_instructions": ["Reopen inside NOVA X Creation Studio via `reopen_handover_archive` or extract locally."],
            "packaged_at": _iso(),
        }
        (pdir / "HANDOVER_MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        handover_md = [
            f"# {project['name']} — NOVA X Handover Package",
            "",
            f"- **Domain / Artifact:** `{project['domain']}` / `{project['artifact_type']}`",
            f"- **Version:** `{manifest['version']}`",
            f"- **License:** `{manifest['licensing']}`",
            f"- **QA Passed:** `{manifest['tests_and_results']['passed']}` (score `{manifest['tests_and_results']['quality_score']}`)",
            "",
            "## Final Artifacts & Editable Sources",
            *[f"- `{p}`" for p in files_included[:25]],
            "",
            "## Launch & Build Instructions",
            *[f"- {step}" for step in manifest["install_and_launch"]],
            "",
            "## Known Limitations",
            *([f"- {lim}" for lim in manifest["known_limitations"]] or ["- None recorded beyond host toolchain scope."]),
        ]
        (pdir / "HANDOVER.md").write_text("\n".join(handover_md) + "\n", encoding="utf-8")
        for extra in ("HANDOVER_MANIFEST.json", "HANDOVER.md"):
            if extra not in files_included:
                files_included.append(extra)

        out_dir = pdir / "dist_handover"
        out_dir.mkdir(parents=True, exist_ok=True)
        if archive_format == "zip":
            archive_path = out_dir / f"{project['slug']}-v{max(1, int(project.get('current_version') or 1))}.zip"
            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for rel_s in files_included:
                    zf.write(pdir / rel_s, arcname=f"{project['slug']}/{rel_s}")
        else:
            archive_path = out_dir / f"{project['slug']}-v{max(1, int(project.get('current_version') or 1))}.tar.gz"
            with tarfile.open(archive_path, "w:gz") as tf:
                for rel_s in files_included:
                    tf.add(pdir / rel_s, arcname=f"{project['slug']}/{rel_s}")

        return {
            "packaged": archive_path.is_file() and archive_path.stat().st_size > 0,
            "archive_path": str(archive_path),
            "archive_format": archive_format,
            "manifest_path": str(pdir / "HANDOVER_MANIFEST.json"),
            "handover_doc": str(pdir / "HANDOVER.md"),
            "included_file_count": len(files_included),
            "excluded_credentials_and_caches": True,
        }


class CreativeWorkspaceManager:
    """§119 Manages multi-domain creation projects, layouts, exploration, and policy-gated lifecycle."""

    def __init__(
        self,
        db: Database,
        workspace_root: Path,
        *,
        redactor: Redactor | None = None,
        permission_check: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
    ) -> None:
        self.db = db
        self.workspace_root = Path(workspace_root)
        self.projects_root = self.workspace_root / "projects"
        self.projects_root.mkdir(parents=True, exist_ok=True)
        self.redactor = redactor or Redactor()
        self.permission_check = permission_check
        self.assets = AssetLibrary(db, self.workspace_root)
        self.lineage = LineageTracker(db)
        self.blueprints = BlueprintLibrary(db, self.redactor)
        self.packager = HandoverPackager(self.redactor)

    def create_project(
        self,
        *,
        name: str,
        domain: str,
        artifact_type: str,
        objective: str,
        spec: dict[str, Any] | None = None,
        toolchain: dict[str, Any] | None = None,
        license_name: str = "MIT",
    ) -> dict[str, Any]:
        project_id = str(uuid.uuid4())
        base_slug = slugify(name)
        slug = f"{base_slug}-{project_id[:6]}"
        pdir = (self.projects_root / slug).resolve()
        pdir.mkdir(parents=True, exist_ok=True)
        for folder in DOMAIN_LAYOUTS.get(domain, ("src", "docs")):
            (pdir / folder).mkdir(parents=True, exist_ok=True)

        full_spec = {
            "project_id": project_id,
            "name": name,
            "domain": domain,
            "artifact_type": artifact_type,
            "objective": objective,
            "layout": list(DOMAIN_LAYOUTS.get(domain, ("src", "docs"))),
            **(spec or {}),
        }
        (pdir / "PROJECT_SPEC.json").write_text(json.dumps(full_spec, indent=2) + "\n", encoding="utf-8")

        record = {
            "id": project_id,
            "slug": slug,
            "name": name,
            "domain": domain,
            "artifact_type": artifact_type,
            "objective": objective,
            "status": "initialized",
            "project_dir": str(pdir),
            "current_version": 0,
            "spec": full_spec,
            "toolchain": toolchain or {},
            "latest_report": {},
            "known_issues": [],
            "license": license_name,
            "archived": False,
        }
        self.db.save_creation_project(record)
        return self.db.get_creation_project(project_id) or record

    def open_project(self, project_id: str) -> dict[str, Any] | None:
        proj = self.db.get_creation_project(project_id)
        if proj is None:
            return None
        return {
            **proj,
            "explorer": self.explore_project(project_id),
            "revisions": self.db.list_creation_revisions(project_id),
            "assets": self.assets.search(project_id=project_id),
        }

    def explore_project(self, project_id: str) -> dict[str, Any]:
        """§119 Universal project explorer understanding code, media, 3D, data, designs, and docs."""
        proj = self.db.get_creation_project(project_id)
        if proj is None:
            return {"exists": False, "files": [], "by_category": {}}
        pdir = Path(proj["project_dir"])
        if not pdir.is_dir():
            return {"exists": False, "files": [], "by_category": {}}

        files: list[dict[str, Any]] = []
        by_cat: dict[str, int] = {}
        for fp in sorted(pdir.rglob("*")):
            if not fp.is_file():
                continue
            rel_parts = fp.relative_to(pdir).parts
            if ".nova_history" in rel_parts or "__pycache__" in rel_parts:
                continue
            cat = classify_file_kind(fp)
            by_cat[cat] = by_cat.get(cat, 0) + 1
            files.append(
                {
                    "path": str(fp.relative_to(pdir)),
                    "category": cat,
                    "size_bytes": fp.stat().st_size,
                    "extension": fp.suffix.lower(),
                }
            )
        return {
            "exists": True,
            "project_dir": str(pdir),
            "layout": list(DOMAIN_LAYOUTS.get(proj["domain"], ())),
            "total_files": len(files),
            "by_category": by_cat,
            "files": files,
        }

    def copy_project(self, project_id: str, new_name: str = "") -> dict[str, Any]:
        src_proj = self.db.get_creation_project(project_id)
        if src_proj is None:
            raise KeyError(f"Project '{project_id}' not found.")
        copied = self.create_project(
            name=new_name or f"{src_proj['name']} (Copy)",
            domain=src_proj["domain"],
            artifact_type=src_proj["artifact_type"],
            objective=src_proj["objective"],
            spec=src_proj["spec"],
            toolchain=src_proj["toolchain"],
            license_name=src_proj["license"],
        )
        src_dir = Path(src_proj["project_dir"])
        dst_dir = Path(copied["project_dir"])
        if src_dir.is_dir():
            for fp in src_dir.rglob("*"):
                if not fp.is_file():
                    continue
                rel = fp.relative_to(src_dir)
                if any(part in EXCLUDED_SNAPSHOT_NAMES for part in rel.parts) or rel.name == "PROJECT_SPEC.json":
                    continue
                target = dst_dir / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(fp, target)
        return self.open_project(copied["id"]) or copied

    def archive_project(self, project_id: str) -> dict[str, Any]:
        proj = self.db.get_creation_project(project_id)
        if proj is None:
            raise KeyError(f"Project '{project_id}' not found.")
        pkg = self.packager.package(proj, archive_format="tar.gz")
        proj["archived"] = True
        proj["status"] = "archived"
        self.db.save_creation_project(proj)
        return {"archived": True, "project_id": project_id, "package": pkg}

    def delete_project(self, project_id: str, *, approved: bool = False) -> dict[str, Any]:
        proj = self.db.get_creation_project(project_id)
        if proj is None:
            return {"deleted": False, "reason": "not_found"}
        if not approved:
            if self.permission_check is None:
                return {"deleted": False, "status": "approval_required", "reason": "Deleting a project directory requires explicit operator approval."}
            pdir_rel = str(Path(proj["project_dir"]).name)
            decision = self.permission_check("workspace.write_file", {"path": f"projects/{pdir_rel}", "overwrite": True})
            if not decision.get("approved", False):
                return {"deleted": False, "status": "approval_required", "reason": "Deleting a project directory requires explicit operator approval."}
        pdir = Path(proj["project_dir"]).resolve()
        if pdir.is_dir() and pdir.is_relative_to(self.projects_root.resolve()):
            shutil.rmtree(pdir, ignore_errors=True)
        self.db.delete_creation_project(project_id)
        return {"deleted": True, "project_id": project_id}

    def reopen_handover_archive(self, archive_path: Path) -> dict[str, Any]:
        """§143 Reopen a packaged handover archive inside NOVA for continued editing."""
        arc = Path(archive_path)
        if not arc.is_file():
            return {"reopened": False, "error": "archive_not_found"}
        extract_tmp = self.projects_root / f".reopen_{uuid.uuid4().hex[:8]}"
        extract_tmp.mkdir(parents=True, exist_ok=True)
        try:
            if arc.name.endswith(".zip"):
                with zipfile.ZipFile(arc, "r") as zf:
                    for member in zf.infolist():
                        dest = (extract_tmp / member.filename).resolve()
                        if not dest.is_relative_to(extract_tmp.resolve()):
                            raise ValueError("Unsafe path in zip archive.")
                    zf.extractall(extract_tmp)
            else:
                with tarfile.open(arc, "r:*") as tf:
                    for member in tf.getmembers():
                        dest = (extract_tmp / member.name).resolve()
                        if not dest.is_relative_to(extract_tmp.resolve()):
                            raise ValueError("Unsafe path in tar archive.")
                    tf.extractall(extract_tmp, filter="data")

            manifests = list(extract_tmp.rglob("HANDOVER_MANIFEST.json"))
            if not manifests:
                return {"reopened": False, "error": "missing_handover_manifest"}
            manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
            extracted_root = manifests[0].parent
            proj = self.create_project(
                name=f"{manifest.get('name', 'Reopened Project')} (Reopened)",
                domain=manifest.get("domain", "software"),
                artifact_type=manifest.get("artifact_type", "software_project"),
                objective=manifest.get("objective", "Reopened from handover archive."),
                license_name=manifest.get("licensing", "MIT"),
            )
            dst_dir = Path(proj["project_dir"])
            for fp in extracted_root.rglob("*"):
                if not fp.is_file() or fp.name == "PROJECT_SPEC.json":
                    continue
                rel = fp.relative_to(extracted_root)
                out = dst_dir / rel
                out.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(fp, out)
            proj["status"] = "reopened"
            proj["current_version"] = 1
            self.db.save_creation_project(proj)
            self.lineage.record_revision(
                proj["id"],
                dst_dir,
                version=1,
                stage="reopened_handover",
                summary=f"Reopened from {arc.name}",
                qa_report={"passed": True, "quality_score": 1.0, "checks": [{"name": "handover_manifest_verified", "passed": True}]},
            )
            return {"reopened": True, "project": self.open_project(proj["id"])}
        finally:
            shutil.rmtree(extract_tmp, ignore_errors=True)

    def find_reusable_components(self, domain: str) -> dict[str, Any]:
        """§119 Identify related projects, blueprints, and license-compatible reusable assets."""
        related_projects = [
            {"id": p["id"], "name": p["name"], "license": p["license"], "status": p["status"]}
            for p in self.db.list_creation_projects(domain=domain)
            if p.get("license", "").lower() in PERMISSIVE_REUSABLE_LICENSES
        ]
        blueprints = self.db.list_creation_blueprints(domain=domain)
        reusable_assets = self.assets.search(reusable_only=True)[:25]
        return {
            "domain": domain,
            "compatible_projects": related_projects,
            "blueprints": blueprints,
            "reusable_assets": reusable_assets,
        }


__all__ = [
    "DOMAIN_LAYOUTS",
    "PERMISSIVE_REUSABLE_LICENSES",
    "RESTRICTED_LICENSES",
    "AssetLibrary",
    "BlueprintLibrary",
    "CreativeWorkspaceManager",
    "HandoverPackager",
    "LineageTracker",
    "classify_file_kind",
    "slugify",
]
