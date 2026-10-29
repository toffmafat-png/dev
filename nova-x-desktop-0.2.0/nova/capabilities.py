"""§113 Feature discovery and technology roadmap.

A registry of what NOVA can actually do *on this machine, right now*, why a
capability is unavailable, and what enabling it would cost. Nothing here
advertises a feature that has not been probed against the real environment.

Two rules shape the module:

* A probe must be cheap and must not import heavy optional dependencies. Module
  presence is checked with ``importlib.util.find_spec``, never by importing.
* Discovering that a library would help is not permission to install it. Every
  recommendation is returned as a proposal carrying its licence, maintenance and
  resource cost, and requires an operator decision (§113).
"""
from __future__ import annotations

import importlib.util
import shutil
import sqlite3
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

STATUS_AVAILABLE = "available"
STATUS_DEGRADED = "degraded"
STATUS_UNAVAILABLE = "unavailable"
STATUS_PLANNED = "planned"
FEATURE_STATUSES = (STATUS_AVAILABLE, STATUS_DEGRADED, STATUS_UNAVAILABLE, STATUS_PLANNED)

REQUIREMENT_BINARY = "binary"
REQUIREMENT_MODULE = "python_module"
REQUIREMENT_SQLITE = "sqlite_feature"
REQUIREMENT_KERNEL = "kernel_feature"
REQUIREMENT_CREDENTIAL = "credential"
REQUIREMENT_CONFIG = "configuration"
REQUIREMENT_KINDS = (
    REQUIREMENT_BINARY,
    REQUIREMENT_MODULE,
    REQUIREMENT_SQLITE,
    REQUIREMENT_KERNEL,
    REQUIREMENT_CREDENTIAL,
    REQUIREMENT_CONFIG,
)

# Probe results are environment facts. They are cached for this long so repeated
# UI refreshes do not spawn subprocesses.
PROBE_TTL_SECONDS = 300.0

# §113: discovering a better library is not authority to install it.
AUTO_INSTALL_PERMITTED = False

Probe = Callable[[], "ProbeResult"]


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


@dataclass(frozen=True)
class ProbeResult:
    ok: bool
    detail: str
    version: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "detail": self.detail, "version": self.version}


@dataclass(frozen=True)
class Requirement:
    kind: str
    name: str
    purpose: str = ""

    def __post_init__(self) -> None:
        if self.kind not in REQUIREMENT_KINDS:
            raise ValueError(f"Unknown requirement kind: {self.kind}")

    def key(self) -> str:
        return f"{self.kind}:{self.name}"

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "name": self.name, "purpose": self.purpose}


@dataclass(frozen=True)
class Feature:
    """One capability, its real requirements, and its honest status."""

    id: str
    label: str
    section: str
    purpose: str
    requirements: tuple[Requirement, ...] = ()
    permissions: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    planned_improvements: tuple[str, ...] = ()
    # Requirements whose absence downgrades rather than disables the feature.
    optional_requirements: tuple[str, ...] = ()
    runtime_cost: str = "low"
    privacy: str = "local_only"
    status: str = STATUS_PLANNED
    reason: str = ""
    missing_requirements: tuple[str, ...] = ()
    degraded_requirements: tuple[str, ...] = ()
    checked_at: str = ""
    last_test: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "section": self.section,
            "purpose": self.purpose,
            "status": self.status,
            "reason": self.reason,
            "requirements": [item.to_dict() for item in self.requirements],
            "missing_requirements": list(self.missing_requirements),
            "degraded_requirements": list(self.degraded_requirements),
            "permissions": list(self.permissions),
            "limitations": list(self.limitations),
            "planned_improvements": list(self.planned_improvements),
            "optional_requirements": list(self.optional_requirements),
            "runtime_cost": self.runtime_cost,
            "privacy": self.privacy,
            "checked_at": self.checked_at,
            "last_test": self.last_test,
        }


@dataclass(frozen=True)
class Recommendation:
    """A proposed dependency or architectural change, awaiting operator decision."""

    id: str
    proposal: str
    solves: str
    licence: str
    maintenance: str
    resource_cost: str
    privacy_impact: str
    risk: str
    decision_required: str
    section: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "proposal": self.proposal,
            "solves": self.solves,
            "licence": self.licence,
            "maintenance": self.maintenance,
            "resource_cost": self.resource_cost,
            "privacy_impact": self.privacy_impact,
            "risk": self.risk,
            "decision_required": self.decision_required,
            "section": self.section,
        }


# --------------------------------------------------------------------------- probes


def probe_binary(name: str) -> Probe:
    def run() -> ProbeResult:
        path = shutil.which(name)
        if not path:
            return ProbeResult(False, f"'{name}' is not on PATH")
        return ProbeResult(True, f"found at {path}")

    return run


def probe_module(name: str) -> Probe:
    def run() -> ProbeResult:
        # find_spec does not execute the module, so an absent or broken optional
        # dependency cannot cost us an import of something as heavy as Playwright.
        try:
            spec = importlib.util.find_spec(name)
        except (ImportError, ValueError, ModuleNotFoundError) as exc:
            return ProbeResult(False, f"cannot resolve '{name}': {exc}")
        if spec is None:
            return ProbeResult(False, f"python module '{name}' is not installed")
        return ProbeResult(True, f"python module '{name}' is importable")

    return run


def probe_sqlite_feature(name: str) -> Probe:
    def run() -> ProbeResult:
        connection = sqlite3.connect(":memory:")
        try:
            if name == "fts5":
                connection.execute("CREATE VIRTUAL TABLE probe_fts USING fts5(body)")
                connection.execute("INSERT INTO probe_fts(body) VALUES ('kw')")
                found = connection.execute("SELECT count(*) FROM probe_fts WHERE probe_fts MATCH 'kw'").fetchone()
                ok = bool(found and found[0] == 1)
                return ProbeResult(ok, "FTS5 compiled in and querying" if ok else "FTS5 table created but MATCH did not work")
            if name == "json1":
                value = connection.execute("""SELECT json_extract('{"a":1}', '$.a')""").fetchone()
                return ProbeResult(bool(value and value[0] == 1), "json1 extension responds")
            return ProbeResult(False, f"no probe implemented for sqlite feature '{name}'")
        except sqlite3.Error as exc:
            return ProbeResult(False, f"sqlite feature '{name}' unavailable: {exc}")
        finally:
            connection.close()

    return run


def probe_user_namespace() -> Probe:
    """Whether unprivileged user namespaces work - the basis of local isolation."""

    def run() -> ProbeResult:
        if shutil.which("unshare") is None:
            return ProbeResult(False, "'unshare' is not available, so namespaces cannot be entered")
        try:
            completed = subprocess.run(
                ["unshare", "--user", "--map-root-user", "true"],
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return ProbeResult(False, f"namespace probe failed: {exc}")
        if completed.returncode == 0:
            return ProbeResult(True, "unprivileged user namespaces are permitted")
        detail = (completed.stderr or b"").decode("utf-8", "replace").strip().splitlines()
        return ProbeResult(False, detail[-1][:200] if detail else f"unshare exited {completed.returncode}")

    return run


def probe_credential(attribute: str) -> Probe:
    def run() -> ProbeResult:
        # Deliberately does not import Settings: the registry is handed the value
        # by the caller so no credential is ever read from the environment twice.
        return ProbeResult(False, f"credential '{attribute}' is not supplied to this probe")

    return run


def probe_flag(name: str) -> Probe:
    def run() -> ProbeResult:
        return ProbeResult(False, f"configuration '{name}' is not enabled")

    return run


def _default_probes() -> dict[str, Probe]:
    probes: dict[str, Probe] = {
        f"{REQUIREMENT_BINARY}:bwrap": probe_binary("bwrap"),
        f"{REQUIREMENT_BINARY}:podman": probe_binary("podman"),
        f"{REQUIREMENT_BINARY}:docker": probe_binary("docker"),
        f"{REQUIREMENT_BINARY}:firejail": probe_binary("firejail"),
        f"{REQUIREMENT_BINARY}:unshare": probe_binary("unshare"),
        f"{REQUIREMENT_BINARY}:git": probe_binary("git"),
        f"{REQUIREMENT_BINARY}:tesseract": probe_binary("tesseract"),
        f"{REQUIREMENT_BINARY}:dbus-send": probe_binary("dbus-send"),
        f"{REQUIREMENT_BINARY}:scrot": probe_binary("scrot"),
        f"{REQUIREMENT_BINARY}:grim": probe_binary("grim"),
        f"{REQUIREMENT_BINARY}:ollama": probe_binary("ollama"),
        f"{REQUIREMENT_MODULE}:playwright": probe_module("playwright"),
        f"{REQUIREMENT_MODULE}:pandas": probe_module("pandas"),
        f"{REQUIREMENT_MODULE}:polars": probe_module("polars"),
        f"{REQUIREMENT_MODULE}:PySide6": probe_module("PySide6"),
        f"{REQUIREMENT_MODULE}:pty": probe_module("pty"),
        f"{REQUIREMENT_MODULE}:resource": probe_module("resource"),
        f"{REQUIREMENT_SQLITE}:fts5": probe_sqlite_feature("fts5"),
        f"{REQUIREMENT_SQLITE}:json1": probe_sqlite_feature("json1"),
        f"{REQUIREMENT_KERNEL}:user_namespace": probe_user_namespace(),
    }
    return probes


# ------------------------------------------------------------------- the catalogue

_B = REQUIREMENT_BINARY
_M = REQUIREMENT_MODULE
_S = REQUIREMENT_SQLITE
_K = REQUIREMENT_KERNEL


def _req(kind: str, name: str, purpose: str = "") -> Requirement:
    return Requirement(kind=kind, name=name, purpose=purpose)


def feature_catalogue() -> tuple[Feature, ...]:
    """The declared capability set, keyed to the specification sections."""
    return (
        Feature(
            id="event_bus",
            label="Event-driven intelligence bus",
            section="§91",
            purpose="Decoupled component communication with schema, dedupe, loop prevention and retry limits.",
            requirements=(_req(_S, "json1", "event payloads are stored as JSON"),),
            limitations=("In-process only: events are not delivered to another NOVA process or after exit.",),
        ),
        Feature(
            id="plugin_framework",
            label="Plugin and skill framework",
            section="§92",
            purpose="Declared-manifest extensions that are validated and permission-scoped before enablement.",
            requirements=(_req(_S, "json1", "manifests are stored as JSON"),),
            optional_requirements=(_req(_K, "user_namespace").key(),),
            limitations=(
                "Plugins declare capabilities; executing untrusted plugin code requires the sandbox feature.",
                "No signed-release verification chain is implemented beyond checksum comparison.",
            ),
            planned_improvements=("Minisign/GPG signature verification against a pinned key.",),
        ),
        Feature(
            id="mcp_client",
            label="Model Context Protocol client",
            section="§93",
            purpose="Connect to local or remote MCP servers, discover tools, validate schemas, scope permissions.",
            requirements=(),
            optional_requirements=(_req(_B, "npx").key(),),
            limitations=(
                "stdio and HTTP JSON-RPC transports only; no SSE resumption.",
                "Server output is treated as untrusted and is never recorded as an observation.",
            ),
        ),
        Feature(
            id="knowledge_search",
            label="Local knowledge engine and hybrid search",
            section="§94",
            purpose="Full-text retrieval over approved documents with provenance, filters and incremental indexing.",
            requirements=(_req(_S, "fts5", "keyword retrieval with ranking"),),
            optional_requirements=(_req(_M, "sentence_transformers").key(), _req(_B, "ollama").key()),
            limitations=(
                "Semantic retrieval needs an embedding provider; without one, ranking is lexical only and says so.",
                "PDF/office parsing is not implemented - text, markdown, JSON, CSV and source files are indexed.",
            ),
            planned_improvements=("Chunked PDF text extraction with page numbers preserved.",),
        ),
        Feature(
            id="context_manager",
            label="Context and memory optimization",
            section="§95",
            purpose="Select relevant context, summarize finished stages, and never compress away constraints.",
            requirements=(),
            limitations=("Summaries are extractive and local; no model call is made to compress context.",),
        ),
        Feature(
            id="terminal_workspace",
            label="Advanced terminal workspace",
            section="§96",
            purpose="Named sessions, streaming output, history, PTY support, task linkage and diagnostic export.",
            requirements=(_req(_M, "pty", "interactive sessions"), _req(_M, "resource", "rlimits on child processes")),
            limitations=("Sessions live in this process; they do not survive an application restart.",),
        ),
        Feature(
            id="workflow_engine",
            label="Workflow visual editor backend",
            section="§97",
            purpose="Validated, acyclic block graphs with dry-run, authorization checks and execution history.",
            requirements=(_req(_S, "json1", "workflow specs are stored as JSON"),),
            limitations=(
                "The specification format and validator are implemented; the Qt drag-and-drop canvas is not.",
                "Natural-language workflow proposals are validated against tools and policy before activation.",
            ),
            planned_improvements=("Native Qt node editor bound to the same specification format.",),
        ),
        Feature(
            id="cross_app_automation",
            label="Cross-application automation",
            section="§98",
            purpose="Coordinate several local applications and services as one verifiable task.",
            requirements=(),
            optional_requirements=(_req(_B, "dbus-send").key(), _req(_M, "playwright").key()),
            limitations=(
                "File, workspace and terminal stages are supported; GUI stages are reported as unavailable.",
                "No browser automation runtime is installed, so web stages are refused rather than simulated.",
            ),
        ),
        Feature(
            id="visual_understanding",
            label="Visual understanding and screen awareness",
            section="§99",
            purpose="Capture and inspect screenshots, read text from images, compare before/after states.",
            requirements=(_req(_B, "scrot", "or grim/spectacle for capture"), _req(_B, "tesseract", "local OCR")),
            limitations=(
                "Visual observations are never merged with verified system facts.",
                "A screenshot cannot prove application state; consequential actions need an API or process result.",
            ),
        ),
        Feature(
            id="developer_environment",
            label="Advanced developer environment",
            section="§100",
            purpose="Repository status, diffs, test discovery, diagnostics and isolated candidate patches.",
            requirements=(_req(_B, "git", "repository inspection"),),
            optional_requirements=(_req(_K, "user_namespace").key(),),
            limitations=(
                "Read-only inspection and candidate patch preparation; production deployment needs explicit approval.",
                "No language server integration, so code navigation is grep-based.",
            ),
        ),
        Feature(
            id="sandbox",
            label="Safe execution sandbox",
            section="§101",
            purpose="Run generated or untrusted code with restricted filesystem, network, resources and lifetime.",
            requirements=(_req(_K, "user_namespace", "namespace isolation"), _req(_M, "resource", "rlimits")),
            optional_requirements=(_req(_B, "bwrap").key(), _req(_B, "podman").key()),
            limitations=(
                "A separate Python process is not a sandbox and is never reported as one.",
                "When no isolation mechanism is available, risky execution is refused rather than downgraded.",
            ),
        ),
        Feature(
            id="health_center",
            label="System health and diagnostics center",
            section="§102",
            purpose="Application, worker, provider, resource, storage and security status with redacted export.",
            requirements=(),
            limitations=("Event-driven refresh; there is no continuous background poller by design.",),
        ),
        Feature(
            id="observability",
            label="Observability and debugging",
            section="§103",
            purpose="Correlated spans with redaction, retention and a local-only default.",
            requirements=(),
            optional_requirements=(_req(_M, "opentelemetry").key(),),
            limitations=(
                "Traces are local by default; external export must be explicitly configured.",
                "OpenTelemetry-compatible in shape, but no OTLP exporter is bundled.",
            ),
        ),
        Feature(
            id="update_manager",
            label="Application updates and version management",
            section="§104",
            purpose="Check a trusted source, verify integrity, back up, migrate and record version history.",
            requirements=(),
            limitations=(
                "Never executes an update script fetched from a remote location.",
                "Applying a package requires the host package manager and operator confirmation.",
            ),
        ),
        Feature(
            id="integration_gateway",
            label="API gateway and integration manager",
            section="§105",
            purpose="One documented surface for providers, services, tools and plugins with health and rate limits.",
            requirements=(),
            limitations=("A successful authentication test is not permission to perform every offered operation.",),
        ),
        Feature(
            id="offline_operation",
            label="Offline and degraded operation",
            section="§106",
            purpose="Stay useful without a provider: local history, indexed search, authorized local tools.",
            requirements=(),
            limitations=(
                "No response is ever fabricated while offline and no research is claimed to have happened.",
                "Queued work revalidates assumptions and permissions before it resumes.",
            ),
        ),
        Feature(
            id="voice_layer",
            label="Voice, audio and speech layer",
            section="§107",
            purpose="Pluggable recognition and synthesis with push-to-talk and a typed-input fallback.",
            requirements=(),
            optional_requirements=(_req(_M, "sounddevice").key(), _req(_B, "arecord").key()),
            limitations=(
                "Voice input enters the same planner and permission engine as typed input.",
                "Speaker recognition would never alone authorize a privileged action.",
            ),
        ),
        Feature(
            id="data_workspace",
            label="Advanced data and knowledge workspace",
            section="§108",
            purpose="Profile CSV/JSON/logs, filter, group, compute statistics and export reproducible analysis.",
            requirements=(),
            optional_requirements=(_req(_M, "pandas").key(), _req(_M, "polars").key()),
            limitations=(
                "Pure-Python streaming profiling is implemented; pandas/Polars are not installed by default.",
                "Generated results are kept distinguishable from source data.",
            ),
        ),
        Feature(
            id="extension_sdk",
            label="Extension API and developer SDK",
            section="§109",
            purpose="Stable contracts for registering tools, declaring permissions and reporting errors.",
            requirements=(),
            limitations=(
                "A plugin cannot bypass authorization by calling internals: only the registry executes tools.",
                "Development mode validates an extension before it can be enabled.",
            ),
        ),
        Feature(
            id="resource_adaptation",
            label="Performance profiling and resource adaptation",
            section="§110",
            purpose="Measure CPU, memory and disk pressure and reduce NOVA's own activity accordingly.",
            requirements=(),
            limitations=(
                "Targets a dual-core machine with about 10 GB of RAM.",
                "Never kills a process NOVA did not start; pressure is answered by doing less, not by force.",
            ),
        ),
        Feature(
            id="privacy_governance",
            label="Privacy-first data governance",
            section="§111",
            purpose="One inventory of what is stored and transmitted, with retention, export and deletion.",
            requirements=(),
            limitations=("Local content is never sent to a service merely because an integration supports uploads.",),
        ),
        Feature(
            id="release_pipeline",
            label="Release engineering and delivery pipeline",
            section="§112",
            purpose="Versioned builds, static and security checks, migration and install tests, release checklist.",
            requirements=(_req(_B, "git", "versioned source"),),
            limitations=("Reproducibility is best-effort: pinned requirements, not a bit-for-bit build.",),
        ),
        Feature(
            id="feature_registry",
            label="Feature discovery and technology roadmap",
            section="§113",
            purpose="This registry: probed status, missing dependencies, limitations and prioritized proposals.",
            requirements=(),
            limitations=("Recommending a dependency is not installing it; every proposal needs an operator decision.",),
        ),
        Feature(
            id="integration_tests",
            label="Integration testing matrix",
            section="§114",
            purpose="Repeatable tests for the expanded stack, reporting precisely what could not be run.",
            requirements=(),
            limitations=("Tests requiring a GUI, D-Bus or network are reported as skipped with the reason named.",),
        ),
    )


# ------------------------------------------------------------------------ registry


@dataclass
class CapabilityRegistry:
    """Probes the environment and reports honest per-feature status."""

    credentials: dict[str, bool] = field(default_factory=dict)
    configuration: dict[str, bool] = field(default_factory=dict)
    probes: dict[str, Probe] = field(default_factory=dict)
    probe_ttl_seconds: float = PROBE_TTL_SECONDS
    _features: dict[str, Feature] = field(default_factory=dict, init=False)
    _cache: dict[str, tuple[float, ProbeResult]] = field(default_factory=dict, init=False)
    _probe_calls: int = field(default=0, init=False)
    _cache_hits: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self.probes = {**_default_probes(), **self.probes}
        for name in self.credentials:
            self.probes[f"{REQUIREMENT_CREDENTIAL}:{name}"] = self._credential_probe(name)
        for name in self.configuration:
            self.probes[f"{REQUIREMENT_CONFIG}:{name}"] = self._config_probe(name)
        self._features = {item.id: item for item in feature_catalogue()}

    def _credential_probe(self, name: str) -> Probe:
        def run() -> ProbeResult:
            present = bool(self.credentials.get(name))
            if present:
                return ProbeResult(True, f"credential '{name}' is configured")
            return ProbeResult(False, f"credential '{name}' is missing; the provider cannot authenticate")

        return run

    def _config_probe(self, name: str) -> Probe:
        def run() -> ProbeResult:
            enabled = bool(self.configuration.get(name))
            if enabled:
                return ProbeResult(True, f"configuration '{name}' is enabled")
            return ProbeResult(False, f"configuration '{name}' is disabled")

        return run

    # -- probing

    def probe(self, requirement: Requirement, *, force: bool = False) -> ProbeResult:
        key = requirement.key()
        cached = self._cache.get(key)
        if cached is not None and not force:
            stored_at, cached_result = cached
            if (datetime.now(UTC) - stored_at).total_seconds() < self.probe_ttl_seconds:
                self._cache_hits += 1
                return cached_result
        runner = self.probes.get(key)
        self._probe_calls += 1
        if runner is None:
            result = ProbeResult(False, f"no probe is registered for '{key}'")
        else:
            try:
                result = runner()
            except Exception as exc:
                # A probe that raises says something true: the capability cannot
                # be confirmed. It is reported, never assumed present.
                result = ProbeResult(False, f"probe for '{key}' failed: {type(exc).__name__}: {exc}")
        if not isinstance(result, ProbeResult):
            result = ProbeResult(False, f"probe for '{key}' returned an invalid result")
        self._cache[key] = (datetime.now(UTC), result)
        return result

    def evaluate(self, feature_id: str, *, force: bool = False) -> Feature:
        feature = self._features.get(feature_id)
        if feature is None:
            raise KeyError(f"Unknown feature: {feature_id}")
        optional = set(feature.optional_requirements)
        missing: list[str] = []
        degraded: list[str] = []
        details: list[str] = []
        for requirement in feature.requirements:
            result = self.probe(requirement, force=force)
            if result.ok:
                continue
            if requirement.key() in optional:
                degraded.append(requirement.key())
                details.append(f"{requirement.name}: {result.detail}")
            else:
                missing.append(requirement.key())
                details.append(f"{requirement.name}: {result.detail}")
        # Optional requirements that are not declared on the feature are probed too,
        # so an absent accelerator downgrades rather than silently disappearing.
        for key in sorted(optional - {item.key() for item in feature.requirements}):
            kind, _, name = key.partition(":")
            result = self.probe(Requirement(kind=kind, name=name), force=force)
            if not result.ok:
                degraded.append(key)
                details.append(f"{name}: {result.detail}")

        if missing:
            status = STATUS_UNAVAILABLE
            reason = "Missing required capability: " + "; ".join(details)
        elif degraded:
            status = STATUS_DEGRADED
            reason = "Available with reduced capability: " + "; ".join(details)
        else:
            status = STATUS_AVAILABLE
            reason = "All declared requirements are present on this machine."
        evaluated = replace(
            feature,
            status=status,
            reason=reason[:600],
            missing_requirements=tuple(missing),
            degraded_requirements=tuple(degraded),
            checked_at=_now(),
        )
        self._features[feature_id] = evaluated
        return evaluated

    def check_all(self, *, force: bool = False) -> list[Feature]:
        return [self.evaluate(feature_id, force=force) for feature_id in sorted(self._features)]

    def record_test(self, feature_id: str, result: str) -> None:
        """Attach the outcome of a real test to a feature (§113 test results)."""
        feature = self._features.get(feature_id)
        if feature is None:
            raise KeyError(f"Unknown feature: {feature_id}")
        self._features[feature_id] = replace(feature, last_test=f"{result} @ {_now()}")

    # -- reporting

    def get(self, feature_id: str) -> Feature:
        feature = self._features.get(feature_id)
        if feature is None:
            raise KeyError(f"Unknown feature: {feature_id}")
        return feature

    def ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._features))

    def unavailable(self) -> list[dict[str, Any]]:
        """Features that cannot run here, with the precise reason why."""
        return [
            {
                "id": item.id,
                "label": item.label,
                "section": item.section,
                "status": item.status,
                "reason": item.reason or "not yet probed",
                "missing_requirements": list(item.missing_requirements),
            }
            for item in self._features.values()
            if item.status in (STATUS_UNAVAILABLE, STATUS_DEGRADED)
        ]

    def snapshot(self) -> dict[str, Any]:
        counts = dict.fromkeys(FEATURE_STATUSES, 0)
        for item in self._features.values():
            counts[item.status] = counts.get(item.status, 0) + 1
        return {
            "generated_at": _now(),
            "counts": counts,
            "probe_calls": self._probe_calls,
            "probe_cache_hits": self._cache_hits,
            "auto_install_permitted": AUTO_INSTALL_PERMITTED,
            "features": [item.to_dict() for item in self._features.values()],
            "unavailable_or_degraded": self.unavailable(),
            "note": (
                "Status reflects this machine at the time it was probed. A feature marked available "
                "is not a claim that it works well, only that its declared requirements are present."
            ),
        }


# ------------------------------------------------------------------- recommendations


def recommendation_catalogue() -> tuple[Recommendation, ...]:
    """Proposals an operator may accept. None of these are installed automatically."""
    return (
        Recommendation(
            id="bubblewrap",
            proposal="Install bubblewrap (bwrap) for sandboxed execution",
            solves="§101 needs a hardened, well-tested isolation launcher; NOVA currently builds namespaces with unshare directly.",
            licence="LGPL-2.1-or-later",
            maintenance="actively maintained; shipped in Debian/Kali repositories",
            resource_cost="negligible; a small setuid-less binary",
            privacy_impact="none; purely local",
            risk="low - it replaces NOVA's hand-built unshare argv with a maintained equivalent",
            decision_required="operator installs the package; NOVA will not install it",
            section="§101",
        ),
        Recommendation(
            id="playwright",
            proposal="Add Playwright for browser automation stages",
            solves="§98 web stages and §99 page inspection are currently refused rather than simulated.",
            licence="Apache-2.0",
            maintenance="actively maintained by Microsoft; large browser download",
            resource_cost="high - browser binaries are hundreds of MB and RAM-hungry on a dual-core machine",
            privacy_impact="browsing happens locally, but page content would enter task context and may reach a provider",
            risk="medium - a browser is a large attack surface and must stay behind the authorization policy",
            decision_required="operator approval plus a disk/RAM assessment on the target machine",
            section="§98",
        ),
        Recommendation(
            id="tesseract",
            proposal="Install tesseract-ocr for local text extraction from images",
            solves="§99 cannot read text from screenshots without an OCR engine.",
            licence="Apache-2.0",
            maintenance="actively maintained; packaged in Kali",
            resource_cost="low to moderate per invocation",
            privacy_impact="none if run locally; screenshots must not be uploaded",
            risk="low - read-only processing of an image NOVA already captured",
            decision_required="operator installs the package and enables screen capture",
            section="§99",
        ),
        Recommendation(
            id="sentence-transformers",
            proposal="Add a local embedding model for semantic retrieval",
            solves="§94 ranking is lexical only; semantic search would find paraphrased matches.",
            licence="Apache-2.0 (library); model licences vary and must be checked individually",
            maintenance="actively maintained; model choice determines download size",
            resource_cost="high - a small model is still hundreds of MB and slow on 2 cores without a GPU",
            privacy_impact="positive if local: document text never leaves the machine. Negative if a remote embedding provider is used instead.",
            risk="medium - only adopt after measuring whether it beats FTS5 on real queries",
            decision_required="operator approval, and a measured benefit over full-text search",
            section="§94",
        ),
        Recommendation(
            id="pandas-or-polars",
            proposal="Add pandas or Polars for the data workspace",
            solves="§108 profiling and grouping of large tabular files without pure-Python loops.",
            licence="BSD-3-Clause (pandas) / MIT (Polars)",
            maintenance="both actively maintained",
            resource_cost="moderate; Polars is lighter and streams, pandas loads more eagerly",
            privacy_impact="none; processing stays local",
            risk="low, but the pure-Python path already covers common cases - measure before adding",
            decision_required="operator approval once a real dataset shows the pure-Python path is too slow",
            section="§108",
        ),
        Recommendation(
            id="opentelemetry-exporter",
            proposal="Add an OpenTelemetry OTLP exporter",
            solves="§103 traces are local-only; an exporter would allow a self-hosted collector.",
            licence="Apache-2.0",
            maintenance="actively maintained by the CNCF",
            resource_cost="low when idle; a network exporter adds a background flush thread",
            privacy_impact="negative by default - traces leave the machine, so redaction must be verified first",
            risk="medium - only with an explicit endpoint, and only after redaction tests pass",
            decision_required="operator configures an endpoint and accepts the data-handling policy",
            section="§103",
        ),
    )


@dataclass(frozen=True)
class PriorityScore:
    """§113 ranking of a proposed extension across the stated criteria."""

    id: str
    usefulness: float
    reliability: float
    performance: float
    privacy: float
    maintenance_cost: float
    user_goal_alignment: float
    total: float
    rationale: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "usefulness": self.usefulness,
            "reliability": self.reliability,
            "performance": self.performance,
            "privacy": self.privacy,
            "maintenance_cost": self.maintenance_cost,
            "user_goal_alignment": self.user_goal_alignment,
            "total": self.total,
            "rationale": list(self.rationale),
        }


PRIORITY_WEIGHTS: dict[str, float] = {
    "usefulness": 0.30,
    "reliability": 0.20,
    "performance": 0.15,
    "privacy": 0.20,
    "maintenance_cost": 0.05,
    "user_goal_alignment": 0.10,
}


def prioritize(proposals: dict[str, dict[str, Any]], *, goals: tuple[str, ...] = ()) -> list[PriorityScore]:
    """Rank proposals by measured criteria rather than by novelty.

    Each proposal supplies 0.0-1.0 scores. ``maintenance_cost`` is inverted: a
    cheap-to-maintain option scores high. Missing criteria are treated as 0 and
    reported in the rationale, so an unevidenced proposal cannot rank first.
    """
    scored: list[PriorityScore] = []
    for proposal_id, values in proposals.items():
        rationale: list[str] = []
        normalized: dict[str, float] = {}
        for criterion in PRIORITY_WEIGHTS:
            raw = values.get(criterion)
            if raw is None:
                normalized[criterion] = 0.0
                rationale.append(f"{criterion}: no evidence supplied, scored 0")
                continue
            try:
                bounded = max(0.0, min(1.0, float(raw)))
            except (TypeError, ValueError):
                bounded = 0.0
                rationale.append(f"{criterion}: unparseable value, scored 0")
            normalized[criterion] = bounded
        goal_text = " ".join(goals).lower()
        if goal_text and str(values.get("solves", "")).lower():
            overlap = sum(1 for word in goal_text.split() if len(word) > 3 and word in str(values.get("solves", "")).lower())
            if overlap:
                rationale.append(f"matches {overlap} term(s) in the stated goals")
        total = round(sum(PRIORITY_WEIGHTS[key] * normalized[key] for key in PRIORITY_WEIGHTS), 4)
        scored.append(
            PriorityScore(
                id=proposal_id,
                usefulness=normalized["usefulness"],
                reliability=normalized["reliability"],
                performance=normalized["performance"],
                privacy=normalized["privacy"],
                maintenance_cost=normalized["maintenance_cost"],
                user_goal_alignment=normalized["user_goal_alignment"],
                total=total,
                rationale=tuple(rationale),
            )
        )
    scored.sort(key=lambda item: (-item.total, item.id))
    return scored


__all__ = [
    "AUTO_INSTALL_PERMITTED",
    "FEATURE_STATUSES",
    "PROBE_TTL_SECONDS",
    "REQUIREMENT_BINARY",
    "REQUIREMENT_CONFIG",
    "REQUIREMENT_CREDENTIAL",
    "REQUIREMENT_KERNEL",
    "REQUIREMENT_MODULE",
    "REQUIREMENT_SQLITE",
    "STATUS_AVAILABLE",
    "STATUS_DEGRADED",
    "STATUS_PLANNED",
    "STATUS_UNAVAILABLE",
    "CapabilityRegistry",
    "Feature",
    "PriorityScore",
    "Probe",
    "ProbeResult",
    "Recommendation",
    "Requirement",
    "feature_catalogue",
    "prioritize",
    "probe_binary",
    "probe_credential",
    "probe_flag",
    "probe_module",
    "probe_sqlite_feature",
    "probe_user_namespace",
    "recommendation_catalogue",
]
