"""§136 Universal capability discovery, §137 toolchain orchestrator, and §147 extensible technology registry.

Examines the actual Kali/Debian Linux host environment before any creation
workflow begins, selects the smallest reliable set of installed tools that can
deliver a real artifact, and evaluates proposed additions against hardware,
licensing, security, and simplicity rules without ever performing silent
system-wide installations.
"""
from __future__ import annotations

import importlib.util
import platform
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

from nova.capabilities import AUTO_INSTALL_PERMITTED
from nova.resources import ResourceBudget, ResourceManager

CREATION_DOMAINS: tuple[str, ...] = (
    "software",
    "writing",
    "visual_design",
    "media",
    "3d",
    "game",
    "web_mobile",
    "database",
    "ml",
    "engineering",
    "simulation",
    "education",
    "business",
    "document",
    "conversion",
    "integration",
    "plugin_capability",
)

SILENT_SYSTEM_INSTALL_PERMITTED = False
DISCOVERY_CACHE_TTL_SECONDS = 300.0


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


@dataclass(frozen=True)
class TechnologyRecord:
    """§147 Approved or candidate technology descriptor."""

    id: str
    name: str
    kind: str  # stdlib | python_module | binary | provider_modality | plugin | external_service
    domains: tuple[str, ...]
    purpose: str
    supported_formats: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ("workspace.read", "workspace.write")
    min_ram_mb: int = 64
    cpu_cost: str = "low"  # low | moderate | heavy
    disk_mb: int = 0
    license: str = "PSF-2.0 / MIT"
    redistribution: str = "permissive"
    maintained: bool = True
    trusted_source: bool = True
    network_required: bool = False
    probe_target: str = ""
    version_args: tuple[str, ...] = ("--version",)
    install_hint: str = ""
    dependencies: tuple[str, ...] = ()
    simpler_alternatives: tuple[str, ...] = ()
    installed: bool = False
    detected_version: str = ""
    detected_path: str = ""
    status_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "domains": list(self.domains),
            "purpose": self.purpose,
            "supported_formats": list(self.supported_formats),
            "permissions": list(self.permissions),
            "resource_requirements": {
                "min_ram_mb": self.min_ram_mb,
                "cpu_cost": self.cpu_cost,
                "disk_mb": self.disk_mb,
            },
            "license": self.license,
            "redistribution": self.redistribution,
            "maintained": self.maintained,
            "trusted_source": self.trusted_source,
            "network_required": self.network_required,
            "install_hint": self.install_hint,
            "dependencies": list(self.dependencies),
            "simpler_alternatives": list(self.simpler_alternatives),
            "installed": self.installed,
            "detected_version": self.detected_version,
            "detected_path": self.detected_path,
            "status_reason": self.status_reason,
        }


@dataclass(frozen=True)
class TechnologyProposal:
    """A candidate library, binary, or external service proposed for adoption (§147)."""

    id: str
    name: str
    kind: str
    domains: tuple[str, ...]
    solves: str
    supported_formats: tuple[str, ...] = ()
    min_ram_mb: int = 256
    cpu_cost: str = "moderate"
    disk_mb: int = 50
    license: str = "MIT"
    redistribution: str = "permissive"
    maintained: bool = True
    trusted_source: bool = True
    network_required: bool = False
    replaces_system_libraries: bool = False
    modifies_apt_repositories: bool = False
    target_platforms: tuple[str, ...] = ("linux",)
    install_scope: str = "project_venv"  # project_venv | apt_package | external_api | system_wide
    install_command: str = ""


@dataclass(frozen=True)
class ProposalEvaluation:
    """Structured result across all eight §147 technology adoption criteria."""

    proposal_id: str
    approved_for_proposal: bool
    decision: str  # use_existing | adopt_with_approval | reject
    criteria: dict[str, dict[str, Any]]
    existing_alternatives: tuple[str, ...]
    rationale: str
    evaluated_at: str = field(default_factory=_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "approved_for_proposal": self.approved_for_proposal,
            "decision": self.decision,
            "criteria": self.criteria,
            "existing_alternatives": list(self.existing_alternatives),
            "rationale": self.rationale,
            "auto_install_permitted": AUTO_INSTALL_PERMITTED,
            "evaluated_at": self.evaluated_at,
        }


def _baseline_technology_catalogue() -> tuple[TechnologyRecord, ...]:
    return (
        TechnologyRecord(
            id="python_runtime",
            name="Python 3 Interpreter & Standard Library",
            kind="stdlib",
            domains=(
                "software",
                "writing",
                "visual_design",
                "media",
                "3d",
                "game",
                "web_mobile",
                "database",
                "ml",
                "engineering",
                "simulation",
                "education",
                "business",
                "document",
                "conversion",
                "integration",
                "plugin_capability",
            ),
            purpose="Primary execution runtime, AST/unittest verification, CSV/JSON/XML/ZIP/WAV/zlib codecs.",
            supported_formats=(".py", ".json", ".csv", ".md", ".html", ".svg", ".png", ".ppm", ".wav", ".avi", ".srt", ".obj", ".stl", ".docx", ".xlsx", ".pdf", ".tar.gz", ".zip"),
            min_ram_mb=48,
            cpu_cost="low",
            license="PSF-2.0",
            probe_target="python3",
        ),
        TechnologyRecord(
            id="sqlite_engine",
            name="SQLite3 Embedded Relational & FTS5 Engine",
            kind="stdlib",
            domains=("database", "software", "web_mobile", "business", "ml", "conversion"),
            purpose="ACID relational schemas, SQL migrations, query plan inspection, and local data engineering.",
            supported_formats=(".sqlite3", ".db", ".sql", ".csv", ".json"),
            min_ram_mb=32,
            cpu_cost="low",
            license="Public Domain",
            probe_target="sqlite3",
        ),
        TechnologyRecord(
            id="pyside6_qt",
            name="PySide6 Native Qt6 Toolkit",
            kind="python_module",
            domains=("software", "visual_design", "game"),
            purpose="Native Kali Linux desktop interfaces and offscreen widget/SVG rendering.",
            supported_formats=(".py", ".svg", ".png"),
            min_ram_mb=180,
            cpu_cost="low",
            disk_mb=160,
            license="LGPL-3.0-only",
            redistribution="dynamic_linking_permissive",
            probe_target="PySide6",
            install_hint="pip install PySide6",
        ),
        TechnologyRecord(
            id="pytest_runner",
            name="Pytest Verification Framework",
            kind="python_module",
            domains=("software", "web_mobile", "game", "database", "ml", "integration", "plugin_capability"),
            purpose="Automated unit, integration, and acceptance testing for generated deliverables.",
            supported_formats=(".py",),
            min_ram_mb=64,
            cpu_cost="low",
            license="MIT",
            probe_target="pytest",
            install_hint="pip install pytest",
        ),
        TechnologyRecord(
            id="nodejs_runtime",
            name="Node.js JavaScript Runtime",
            kind="binary",
            domains=("software", "web_mobile", "integration", "game"),
            purpose="Frontend JavaScript syntax validation, Node CLI/API execution, and web asset tooling.",
            supported_formats=(".js", ".mjs", ".cjs", ".json"),
            min_ram_mb=96,
            cpu_cost="low",
            license="MIT",
            probe_target="node",
            install_hint="sudo apt-get install -y nodejs",
            simpler_alternatives=("python_runtime",),
        ),
        TechnologyRecord(
            id="gcc_toolchain",
            name="GNU C/C++ Compiler (gcc / g++)",
            kind="binary",
            domains=("software", "engineering", "simulation"),
            purpose="Compiled C/C++ system utilities, numerical kernels, and host firmware simulation.",
            supported_formats=(".c", ".h", ".cpp", ".hpp", ".out"),
            min_ram_mb=128,
            cpu_cost="moderate",
            license="GPL-3.0-with-GCC-exception",
            probe_target="gcc",
            install_hint="sudo apt-get install -y build-essential",
            simpler_alternatives=("python_runtime",),
        ),
        TechnologyRecord(
            id="rust_toolchain",
            name="Rust Compiler & Cargo",
            kind="binary",
            domains=("software", "engineering"),
            purpose="Memory-safe compiled CLIs and native libraries.",
            supported_formats=(".rs", ".toml"),
            min_ram_mb=512,
            cpu_cost="heavy",
            disk_mb=900,
            license="MIT / Apache-2.0",
            probe_target="rustc",
            install_hint="sudo apt-get install -y rustc cargo",
            simpler_alternatives=("gcc_toolchain", "python_runtime"),
        ),
        TechnologyRecord(
            id="go_toolchain",
            name="Go Toolchain",
            kind="binary",
            domains=("software", "integration", "web_mobile"),
            purpose="Static backend services and concurrent network utilities.",
            supported_formats=(".go",),
            min_ram_mb=256,
            cpu_cost="moderate",
            disk_mb=400,
            license="BSD-3-Clause",
            probe_target="go",
             version_args=("version",),
            install_hint="sudo apt-get install -y golang-go",
            simpler_alternatives=("python_runtime",),
        ),
        TechnologyRecord(
            id="imagemagick_convert",
            name="ImageMagick Raster & Vector Processor",
            kind="binary",
            domains=("visual_design", "media", "conversion", "document"),
            purpose="SVG-to-PNG rasterization, format conversion, thumbnails, montage, and animated GIF export.",
            supported_formats=(".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ppm", ".bmp", ".ico", ".pdf"),
            min_ram_mb=96,
            cpu_cost="low",
            disk_mb=35,
            license="ImageMagick",
            probe_target="convert",
            version_args=("-version",),
            install_hint="sudo apt-get install -y imagemagick",
            simpler_alternatives=("python_runtime",),
        ),
        TechnologyRecord(
            id="pillow_imaging",
            name="Pillow Python Imaging Library",
            kind="python_module",
            domains=("visual_design", "media", "conversion"),
            purpose="In-process raster editing, typography, alpha compositing, and multi-format export.",
            supported_formats=(".png", ".jpg", ".webp", ".gif", ".bmp", ".tiff", ".ico"),
            min_ram_mb=64,
            cpu_cost="low",
            disk_mb=15,
            license="HPND (MIT-like)",
            probe_target="PIL",
            install_hint="pip install Pillow",
            simpler_alternatives=("imagemagick_convert", "python_runtime"),
        ),
        TechnologyRecord(
            id="ffmpeg_media",
            name="FFmpeg Audio/Video Production Suite",
            kind="binary",
            domains=("media", "conversion", "game"),
            purpose="MP4/WebM encoding, audio muxing, subtitle burn-in, trimming, and container transcoding.",
            supported_formats=(".mp4", ".webm", ".mkv", ".avi", ".mov", ".wav", ".mp3", ".ogg", ".flac", ".srt", ".vtt"),
            min_ram_mb=160,
            cpu_cost="moderate",
            disk_mb=120,
            license="LGPL-2.1+ / GPL-2.0+",
            redistribution="check_codec_build_flags",
            probe_target="ffmpeg",
            version_args=("-version",),
            install_hint="sudo apt-get install -y ffmpeg",
            simpler_alternatives=("python_runtime", "imagemagick_convert"),
        ),
        TechnologyRecord(
            id="openscad_cad",
            name="OpenSCAD Parametric 3D Solid Modeller",
            kind="binary",
            domains=("3d", "engineering"),
            purpose="Deterministic script-driven CSG solid modelling and watertight STL/OFF/DXF export.",
            supported_formats=(".scad", ".stl", ".off", ".dxf", ".svg", ".png"),
            min_ram_mb=256,
            cpu_cost="moderate",
            disk_mb=90,
            license="GPL-2.0+",
            probe_target="openscad",
            install_hint="sudo apt-get install -y openscad",
            simpler_alternatives=("python_runtime",),
        ),
        TechnologyRecord(
            id="blender_3d",
            name="Blender 3D & Animation Engine",
            kind="binary",
            domains=("3d", "media", "game"),
            purpose="Full 3D mesh sculpting, rigging, Cycles/EEVEE rendering, and glTF/FBX/OBJ pipelines.",
            supported_formats=(".blend", ".obj", ".stl", ".gltf", ".glb", ".fbx", ".png", ".mp4"),
            min_ram_mb=2048,
            cpu_cost="heavy",
            disk_mb=950,
            license="GPL-3.0+",
            probe_target="blender",
            install_hint="sudo apt-get install -y blender",
            simpler_alternatives=("openscad_cad", "python_runtime"),
        ),
        TechnologyRecord(
            id="freecad_eng",
            name="FreeCAD Parametric Mechanical CAD",
            kind="binary",
            domains=("3d", "engineering"),
            purpose="STEP/IGES mechanical assemblies, technical drawings, and constraint sketches.",
            supported_formats=(".FCStd", ".step", ".stp", ".iges", ".stl", ".obj"),
            min_ram_mb=1024,
            cpu_cost="moderate",
            disk_mb=650,
            license="LGPL-2.0+",
            probe_target="freecadcmd",
            install_hint="sudo apt-get install -y freecad",
            simpler_alternatives=("openscad_cad", "python_runtime"),
        ),
        TechnologyRecord(
            id="godot_engine",
            name="Godot Game Engine",
            kind="binary",
            domains=("game",),
            purpose="2D/3D scene tree, physics, GDScript gameplay, and multi-platform export.",
            supported_formats=(".godot", ".tscn", ".tres", ".gd"),
            min_ram_mb=512,
            cpu_cost="moderate",
            disk_mb=180,
            license="MIT",
            probe_target="godot4",
            install_hint="sudo apt-get install -y godot3",
            simpler_alternatives=("python_runtime", "nodejs_runtime"),
        ),
        TechnologyRecord(
            id="scikit_learn_ml",
            name="scikit-learn Classical ML Suite",
            kind="python_module",
            domains=("ml", "simulation"),
            purpose="Low-RAM tabular pipelines, cross-validation, classification/regression, and metrics.",
            supported_formats=(".py", ".pkl", ".json", ".csv"),
            min_ram_mb=192,
            cpu_cost="moderate",
            disk_mb=90,
            license="BSD-3-Clause",
            probe_target="sklearn",
            install_hint="pip install scikit-learn",
            simpler_alternatives=("python_runtime",),
        ),
        TechnologyRecord(
            id="pytorch_dl",
            name="PyTorch Deep Learning Framework",
            kind="python_module",
            domains=("ml",),
            purpose="Neural network training and tensor autograd (heavy on dual-core CPU hosts).",
            supported_formats=(".pt", ".pth", ".onnx"),
            min_ram_mb=3072,
            cpu_cost="heavy",
            disk_mb=2200,
            license="BSD-3-Clause",
            probe_target="torch",
            install_hint="pip install torch --index-url https://download.pytorch.org/whl/cpu",
            simpler_alternatives=("scikit_learn_ml", "python_runtime"),
        ),
        TechnologyRecord(
            id="pandoc_docs",
            name="Pandoc Universal Document Converter",
            kind="binary",
            domains=("document", "writing", "education", "conversion"),
            purpose="Rich conversion across Markdown, DOCX, HTML, EPUB, LaTeX, and slide formats.",
            supported_formats=(".md", ".docx", ".html", ".epub", ".rst", ".tex"),
            min_ram_mb=128,
            cpu_cost="low",
            disk_mb=140,
            license="GPL-2.0+",
            probe_target="pandoc",
            install_hint="sudo apt-get install -y pandoc",
            simpler_alternatives=("python_runtime",),
        ),
        TechnologyRecord(
            id="libreoffice_suite",
            name="LibreOffice Headless Publishing Suite",
            kind="binary",
            domains=("document", "business", "conversion"),
            purpose="Full-fidelity DOCX/ODT/XLSX/PPTX layout rendering and PDF export.",
            supported_formats=(".docx", ".odt", ".xlsx", ".ods", ".pptx", ".odp", ".pdf"),
            min_ram_mb=768,
            cpu_cost="moderate",
            disk_mb=850,
            license="MPL-2.0",
            probe_target="soffice",
            install_hint="sudo apt-get install -y libreoffice-core libreoffice-writer",
            simpler_alternatives=("pandoc_docs", "python_runtime"),
        ),
        TechnologyRecord(
            id="postgresql_client",
            name="PostgreSQL Client & Tools (psql)",
            kind="binary",
            domains=("database", "software", "web_mobile"),
            purpose="Client connectivity and migration execution for authorized PostgreSQL servers.",
            supported_formats=(".sql", ".csv"),
            permissions=("workspace.read", "network.database"),
            min_ram_mb=64,
            cpu_cost="low",
            license="PostgreSQL",
            network_required=True,
            probe_target="psql",
            install_hint="sudo apt-get install -y postgresql-client",
            simpler_alternatives=("sqlite_engine",),
        ),
        TechnologyRecord(
            id="provider_ai_generation",
            name="Configured AI Model Provider (Text/Code/Multimodal)",
            kind="provider_modality",
            domains=CREATION_DOMAINS,
            purpose="Optional cloud or local OpenAI-compatible inference when credentials are configured.",
            supported_formats=(".md", ".py", ".json", ".svg"),
            permissions=("provider.inference",),
            min_ram_mb=32,
            cpu_cost="low",
            license="Provider-specific",
            redistribution="subject_to_provider_terms",
            network_required=True,
            probe_target="ai_provider",
            simpler_alternatives=("python_runtime",),
        ),
    )


def _probe_binary_version(binary: str, version_args: tuple[str, ...]) -> tuple[bool, str, str]:
    resolved = shutil.which(binary)
    if not resolved:
        return False, "", f"'{binary}' not found on PATH"
    try:
        completed = subprocess.run(
            [resolved, *version_args],
            capture_output=True,
            text=True,
            timeout=2.5,
            check=False,
        )
        raw = (completed.stdout or completed.stderr or "").strip().splitlines()
        first_line = raw[0].strip()[:120] if raw else "installed"
        return True, first_line, f"found at {resolved}"
    except (OSError, subprocess.SubprocessError) as exc:
        return True, "unknown", f"found at {resolved} (version probe warning: {type(exc).__name__})"


class TechnologyRegistry:
    """§147 Extensible registry of approved tools, libraries, models, plugins, and services."""

    def __init__(
        self,
        *,
        resources: ResourceManager | None = None,
        provider_status_fn: Callable[[], dict[str, Any]] | None = None,
        plugins_fn: Callable[[], list[dict[str, Any]]] | None = None,
        integrations_fn: Callable[[], list[dict[str, Any]]] | None = None,
    ) -> None:
        self._resources = resources or ResourceManager()
        self._provider_status_fn = provider_status_fn or (lambda: {"configured": False, "capabilities": ()})
        self._plugins_fn = plugins_fn or list
        self._integrations_fn = integrations_fn or list
        self._records: dict[str, TechnologyRecord] = {item.id: item for item in _baseline_technology_catalogue()}
        self._proposals: list[dict[str, Any]] = []
        self._last_probe_monotonic: float = 0.0

    def register(self, record: TechnologyRecord) -> TechnologyRecord:
        probed = self._probe_one(record)
        self._records[probed.id] = probed
        return probed

    def _probe_one(self, rec: TechnologyRecord) -> TechnologyRecord:
        if rec.kind == "stdlib":
            if rec.probe_target == "python3":
                return replace(
                    rec,
                    installed=True,
                    detected_version=f"Python {sys.version.split()[0]}",
                    detected_path=sys.executable,
                    status_reason="active interpreter",
                )
            if rec.probe_target == "sqlite3":
                import sqlite3

                return replace(
                    rec,
                    installed=True,
                    detected_version=f"SQLite {sqlite3.sqlite_version}",
                    detected_path="stdlib:sqlite3",
                    status_reason="built into Python stdlib",
                )
            found = importlib.util.find_spec(rec.probe_target) is not None
            return replace(rec, installed=found, detected_version=sys.version.split()[0] if found else "", status_reason="stdlib")

        if rec.kind == "python_module":
            try:
                spec = importlib.util.find_spec(rec.probe_target)
            except (ImportError, ValueError):
                spec = None
            if spec is None:
                return replace(rec, installed=False, detected_version="", detected_path="", status_reason=f"module '{rec.probe_target}' not installed")
            origin = str(spec.origin or "installed")
            return replace(rec, installed=True, detected_version="present", detected_path=origin, status_reason="importable in current Python environment")

        if rec.kind == "binary":
            ok, ver, detail = _probe_binary_version(rec.probe_target, rec.version_args)
            resolved = shutil.which(rec.probe_target) or ""
            return replace(rec, installed=ok, detected_version=ver, detected_path=resolved, status_reason=detail)

        if rec.kind == "provider_modality":
            pstate = self._provider_status_fn()
            configured = bool(pstate.get("configured"))
            caps = tuple(pstate.get("capabilities") or ())
            return replace(
                rec,
                installed=configured,
                detected_version=",".join(caps) if caps else ("configured" if configured else ""),
                detected_path="provider:openai-compatible" if configured else "",
                status_reason="AI provider credentials configured" if configured else "AI_API_KEY not configured; running local deterministic engines",
            )

        return rec

    def refresh(self, *, force: bool = False) -> list[TechnologyRecord]:
        now = time.monotonic()
        if not force and self._last_probe_monotonic and (now - self._last_probe_monotonic) < DISCOVERY_CACHE_TTL_SECONDS:
            return list(self._records.values())
        for key, rec in list(self._records.items()):
            self._records[key] = self._probe_one(rec)
        self._last_probe_monotonic = now
        return list(self._records.values())

    def list_technologies(self, *, domain: str = "", installed_only: bool = False, refresh: bool = False) -> list[dict[str, Any]]:
        records = self.refresh(force=refresh)
        out: list[dict[str, Any]] = []
        for rec in records:
            if domain and domain not in rec.domains:
                continue
            if installed_only and not rec.installed:
                continue
            out.append(rec.to_dict())
        return out

    def get(self, tech_id: str) -> TechnologyRecord | None:
        self.refresh(force=False)
        return self._records.get(tech_id)

    def evaluate_proposal(self, proposal: TechnologyProposal) -> ProposalEvaluation:
        """§147 Evaluate a candidate technology across all eight adoption criteria."""
        self.refresh(force=False)
        budget: ResourceBudget = self._resources.assess()
        sample = budget.sample
        avail_ram_mb = max(256, int(sample.memory_available_mb if sample else 2048))
        cpu_count = int(sample.cpu_count if sample and sample.cpu_count else 2)
        host_os = platform.system().lower()

        # Find already-installed simpler tools covering the same domain & requested formats.
        req_formats = set(proposal.supported_formats)
        existing_covering: list[str] = []
        for rec in self._records.values():
            if not rec.installed:
                continue
            domain_overlap = bool(set(rec.domains) & set(proposal.domains))
            format_covered = not req_formats or req_formats.issubset(set(rec.supported_formats))
            if domain_overlap and format_covered and rec.cpu_cost == "low":
                existing_covering.append(rec.id)

        solves_ok = bool(proposal.solves.strip()) and bool(proposal.domains)
        compat_ok = host_os in {p.lower() for p in proposal.target_platforms}
        trust_ok = bool(proposal.maintained and proposal.trusted_source)
        license_ok = bool(proposal.license.strip()) and proposal.redistribution != "prohibited"
        hardware_ok = proposal.min_ram_mb <= max(512, int(avail_ram_mb * 0.85)) and not (
            cpu_count <= 2 and proposal.min_ram_mb > 2500
        )
        security_ok = not proposal.replaces_system_libraries and not proposal.modifies_apt_repositories
        install_ok = proposal.install_scope in {"project_venv", "apt_package", "external_api"} and not proposal.replaces_system_libraries
        simpler_adequate = len(existing_covering) > 0 and bool(req_formats)

        criteria = {
            "solves_problem": {"ok": solves_ok, "detail": proposal.solves or "missing problem statement"},
            "host_compatible": {"ok": compat_ok, "detail": f"host={host_os}, targets={list(proposal.target_platforms)}"},
            "maintained_and_trustworthy": {
                "ok": trust_ok,
                "detail": f"maintained={proposal.maintained}, trusted_source={proposal.trusted_source}",
            },
            "license_and_redistribution": {
                "ok": license_ok,
                "detail": f"license={proposal.license} ({proposal.redistribution})",
            },
            "hardware_fit": {
                "ok": hardware_ok,
                "detail": f"requires {proposal.min_ram_mb} MB RAM ({proposal.cpu_cost} CPU); available ~{avail_ram_mb} MB on {cpu_count} cores",
            },
            "security_and_network": {
                "ok": security_ok,
                "detail": f"network_required={proposal.network_required}, replaces_system_libs={proposal.replaces_system_libraries}",
            },
            "install_and_update_implications": {
                "ok": install_ok,
                "detail": f"scope={proposal.install_scope}, modifies_repos={proposal.modifies_apt_repositories}",
            },
            "simpler_existing_adequate": {
                "adeq_existing_found": simpler_adequate,
                "existing_tools": existing_covering,
                "detail": (
                    f"Existing installed tools already cover {sorted(req_formats)}: {', '.join(existing_covering)}"
                    if simpler_adequate
                    else "No simpler installed tool covers all target capabilities/formats."
                ),
            },
        }

        hard_ok = solves_ok and compat_ok and trust_ok and license_ok and hardware_ok and security_ok and install_ok
        if not hard_ok:
            failed = [k for k, v in criteria.items() if k != "simpler_existing_adequate" and not v.get("ok")]
            decision = "reject"
            approved = False
            rationale = f"Rejected candidate '{proposal.name}': failed {', '.join(failed)}."
        elif simpler_adequate:
            decision = "use_existing"
            approved = False
            rationale = (
                f"Deferred '{proposal.name}': simpler installed tools ({', '.join(existing_covering)}) "
                "already satisfy the requested domain and formats (§147 anti-sprawl rule)."
            )
        else:
            decision = "adopt_with_approval"
            approved = True
            rationale = (
                f"Candidate '{proposal.name}' passes compatibility, license, security, and hardware checks; "
                f"operator approval required before running `{proposal.install_command or 'install'}`."
            )

        evaluation = ProposalEvaluation(
            proposal_id=proposal.id,
            approved_for_proposal=approved,
            decision=decision,
            criteria=criteria,
            existing_alternatives=tuple(existing_covering),
            rationale=rationale,
        )
        self._proposals.append({"proposal": proposal.id, "name": proposal.name, **evaluation.to_dict()})
        return evaluation

    def proposals_history(self) -> list[dict[str, Any]]:
        return list(self._proposals)


class CapabilityDiscovery:
    """§136 Examines the local environment to determine real creation capabilities and gaps."""

    def __init__(self, registry: TechnologyRegistry, resources: ResourceManager) -> None:
        self.registry = registry
        self.resources = resources

    def discover(self, *, refresh: bool = False) -> dict[str, Any]:
        records = self.registry.refresh(force=refresh)
        budget = self.resources.assess()

        installed_apps = [r.to_dict() for r in records if r.kind == "binary" and r.installed]
        dev_tools = [
            r.to_dict()
            for r in records
            if r.installed and ("software" in r.domains or r.id in {"sqlite_engine", "pytest_runner", "nodejs_runtime", "gcc_toolchain"})
        ]
        formats: set[str] = set()
        for r in records:
            if r.installed:
                formats.update(r.supported_formats)

        provider_state = self.registry._provider_status_fn()
        plugins = self.registry._plugins_fn()
        integrations = self.registry._integrations_fn()

        missing_deps = [
            {
                "id": r.id,
                "name": r.name,
                "domains": list(r.domains),
                "install_hint": r.install_hint,
                "simpler_installed_fallbacks": [alt for alt in r.simpler_alternatives if (self.registry.get(alt) and self.registry.get(alt).installed)],  # type: ignore[union-attr]
            }
            for r in records
            if not r.installed and r.kind in {"binary", "python_module"}
        ]

        local_domains = sorted(
            domain
            for domain in CREATION_DOMAINS
            if any(r.installed and not r.network_required and domain in r.domains for r in records)
        )
        external_service_tasks = [
            "photorealistic_or_cinematic_generative_video",
            "bespoke_neural_image_synthesis_without_configured_provider",
            "live_cloud_deployment_or_payment_processing",
            "remote_postgresql_without_credentials",
        ]
        hardware_exceeded: list[str] = []
        s_cpu = int(budget.sample.cpu_count if budget.sample and budget.sample.cpu_count else 2)
        s_mem = int(budget.sample.memory_total_mb if budget.sample and budget.sample.memory_total_mb else 10_240)
        if s_cpu <= 2 or s_mem <= 12_288:
            hardware_exceeded.extend(
                [
                    "large_local_llm_or_diffusion_training",
                    "multi_gigabyte_neural_checkpoint_finetuning",
                    "heavy_cycles_3d_path_tracing_animations",
                ]
            )

        return {
            "checked_at": _iso(),
            "installed_applications": installed_apps,
            "development_tools": dev_tools,
            "processable_formats": sorted(formats),
            "configured_providers": provider_state,
            "supported_modalities": list(provider_state.get("capabilities") or ["deterministic_local_text_code_svg_png_wav_avi_3d_docs"]),
            "available_plugins": plugins,
            "reachable_integrations": integrations,
            "missing_optional_dependencies": missing_deps,
            "local_runnable_domains": local_domains,
            "requires_external_service": external_service_tasks,
            "exceeds_local_hardware_or_budget": hardware_exceeded,
            "hardware_envelope": budget.to_dict(),
            "silent_install_permitted": SILENT_SYSTEM_INSTALL_PERMITTED,
        }

    def propose_setup_plan(self, domain: str, required_format: str = "") -> dict[str, Any]:
        """§136 Generate a safe, permission-gated setup plan when an optional capability is missing."""
        records = self.registry.refresh(force=False)
        installed_matching = [
            r
            for r in records
            if r.installed and domain in r.domains and (not required_format or required_format in r.supported_formats)
        ]
        candidates = [
            r
            for r in records
            if not r.installed and domain in r.domains and (not required_format or required_format in r.supported_formats)
        ]
        recommended = candidates[0] if candidates else None
        return {
            "domain": domain,
            "required_format": required_format,
            "already_satisfiable_locally": bool(installed_matching),
            "installed_alternatives": [r.id for r in installed_matching],
            "recommended_addition": recommended.to_dict() if recommended else None,
            "setup_steps": (
                [
                    f"Verify operator approval under AutonomyPolicy before running `{recommended.install_hint}`.",
                    "Prefer project-local `.venv` for Python packages; never replace core system libraries or edit APT sources automatically.",
                    "Re-run capability discovery (`refresh=True`) and smoke-test the tool in Sandbox before project registration.",
                ]
                if recommended and recommended.install_hint
                else ["Use installed local deterministic fallback toolchain; no external package is available in the approved catalogue."]
            ),
            "requires_authorization": True,
            "auto_executed": False,
        }


class ToolchainOrchestrator:
    """§137 Selects compatible, installed toolchains and emits project dependency manifests."""

    def __init__(self, registry: TechnologyRegistry) -> None:
        self.registry = registry

    def select_toolchain(
        self,
        domain: str,
        *,
        preferred_language: str = "python",
        requested_formats: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        records = self.registry.refresh(force=False)
        by_id = {r.id: r for r in records}

        selected: list[TechnologyRecord] = []
        missing_optional: list[dict[str, str]] = []

        # Always anchor on Python runtime when available.
        if by_id["python_runtime"].installed:
            selected.append(by_id["python_runtime"])

        domain_preferences: dict[str, tuple[str, ...]] = {
            "software": ("gcc_toolchain",) if preferred_language in {"c", "cpp"} else (("nodejs_runtime",) if preferred_language in {"js", "javascript"} else ("pyside6_qt", "pytest_runner")),
            "web_mobile": ("nodejs_runtime", "sqlite_engine", "pytest_runner"),
            "visual_design": ("imagemagick_convert", "pillow_imaging"),
            "media": ("ffmpeg_media", "imagemagick_convert"),
            "3d": ("openscad_cad", "blender_3d", "imagemagick_convert"),
            "engineering": ("openscad_cad", "freecad_eng", "gcc_toolchain"),
            "game": ("godot_engine", "pytest_runner", "imagemagick_convert"),
            "database": ("sqlite_engine", "postgresql_client", "pytest_runner"),
            "ml": ("scikit_learn_ml", "sqlite_engine", "imagemagick_convert"),
            "simulation": ("scikit_learn_ml", "imagemagick_convert"),
            "document": ("pandoc_docs", "libreoffice_suite"),
            "writing": ("pandoc_docs",),
            "education": ("pandoc_docs", "pytest_runner"),
            "business": ("sqlite_engine", "pandoc_docs"),
            "conversion": ("imagemagick_convert", "ffmpeg_media", "pandoc_docs", "sqlite_engine"),
            "integration": ("pytest_runner", "sqlite_engine"),
            "plugin_capability": ("pytest_runner",),
        }

        for tech_id in domain_preferences.get(domain, ("pytest_runner",)):
            rec = by_id.get(tech_id)
            if rec is None:
                continue
            if rec.installed:
                if rec not in selected:
                    selected.append(rec)
            else:
                missing_optional.append(
                    {
                        "id": rec.id,
                        "name": rec.name,
                        "purpose": rec.purpose,
                        "install_hint": rec.install_hint,
                    }
                )

        covered_formats: set[str] = set()
        for item in selected:
            covered_formats.update(item.supported_formats)
        uncovered = sorted(set(requested_formats) - covered_formats)

        return {
            "domain": domain,
            "preferred_language": preferred_language,
            "selected_tools": [
                {
                    "id": item.id,
                    "name": item.name,
                    "version": item.detected_version,
                    "path": item.detected_path,
                    "license": item.license,
                }
                for item in selected
            ],
            "missing_optional_tools": missing_optional,
            "uncovered_formats": uncovered,
            "python_constraint": f">={sys.version_info.major}.{sys.version_info.minor}",
            "licenses": sorted({item.license for item in selected}),
            "uses_existing_environment": True,
        }


__all__ = [
    "CREATION_DOMAINS",
    "SILENT_SYSTEM_INSTALL_PERMITTED",
    "CapabilityDiscovery",
    "ProposalEvaluation",
    "TechnologyProposal",
    "TechnologyRecord",
    "TechnologyRegistry",
    "ToolchainOrchestrator",
]
