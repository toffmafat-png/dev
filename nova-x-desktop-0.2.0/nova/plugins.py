"""§92 Plugin & skill marketplace and §109 Extension API & Developer SDK.

Allows NOVA to gain new capabilities without rewriting its core while keeping
strict permission boundaries:

* Every plugin declares all eleven §92 manifest sections (identity/version,
  purpose, operations, dependencies, required permissions, input/output schemas,
  network requirements, filesystem requirements, side effects, timeout/resource
  limits, tests & compatibility) plus explicit trust metadata.
* Installation never grants unrestricted access or auto-enables a plugin. A
  plugin executes only the permissions explicitly granted at enablement, and
  external plugin entrypoints run inside :class:`nova.sandbox.Sandbox`.
* Candidate plugins live in a separate staging directory, run their tests in
  isolation, have their permissions inspected, and can be registered only after
  checks pass.
* §109's :class:`ExtensionContext` exposes workspace scope, configuration,
  cancellation, redacted logging and structured error reporting — never
  ``Database``, ``AutonomyPolicy`` or internal administrative objects — and
  development-mode validation rejects code that imports internal policy/DB
  modules directly.
"""
from __future__ import annotations

import ast
import hashlib
import json
import platform
import shutil
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any

from pydantic import BaseModel, Field, ValidationError, field_validator

from nova import __version__
from nova.observability import Redactor
from nova.sandbox import (
    RISK_PURE,
    RISK_SCOPED_WRITE,
    RISK_UNTRUSTED_CODE,
    STATUS_COMPLETED,
    Sandbox,
    SandboxPolicy,
)
from nova.tools.registry import ToolDefinition, ToolOutcome, ToolRegistry
from nova.updates import parse_version

PLUGIN_SCHEMA_VERSION = "nova-plugin-v1"
SDK_API_VERSION = "1.0"

PLUGIN_CATEGORIES = (
    "development",
    "research",
    "document_processing",
    "data_analysis",
    "computer_operations",
    "model_provider",
    "external_integration",
)

NETWORK_MODES = ("none", "allowlist")
FILESYSTEM_MODES = ("none", "read_workspace", "scoped_write")

# Internal modules an extension must never import to bypass ToolRegistry or
# mutate the permissions database (§109).
FORBIDDEN_EXTENSION_IMPORTS = frozenset(
    {
        "nova.db",
        "nova.autonomy",
        "nova.desktop.secrets",
        "nova.sandbox_child",
        "ctypes",
    }
)


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


class PluginOperationSpec(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    description: str = Field(min_length=3, max_length=400)
    input_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object", "properties": {}})
    output_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object", "properties": {}})
    autonomy_class: str = Field(default="approval_required")

    @field_validator("autonomy_class")
    @classmethod
    def _check_autonomy(cls, value: str) -> str:
        if value not in {"routine", "approval_required"}:
            raise ValueError("autonomy_class must be 'routine' or 'approval_required'")
        return value

    @field_validator("input_schema", "output_schema")
    @classmethod
    def _check_schema(cls, value: dict[str, Any]) -> dict[str, Any]:
        if value.get("type") != "object":
            raise ValueError("operation schema root must declare type='object'")
        return value


class PluginCompatibility(BaseModel):
    min_nova_version: str = "0.2.0"
    max_nova_version: str = ""
    min_python: str = "3.11"
    platforms: list[str] = Field(default_factory=lambda: ["linux"])


class PluginTrust(BaseModel):
    publisher: str = "local_developer"
    repository: str = ""
    sha256: str = ""
    signed: bool = False
    signature_ref: str = ""
    trusted: bool = False


class PluginManifest(BaseModel):
    """Complete §92 plugin declaration."""

    schema_version: str = PLUGIN_SCHEMA_VERSION
    sdk_version: str = SDK_API_VERSION
    name: str = Field(min_length=2, max_length=64, pattern=r"^[a-z][a-z0-9_\-]*$")
    version: str = Field(min_length=5, max_length=32)
    purpose: str = Field(min_length=5, max_length=500)
    category: str = "development"
    operations: list[PluginOperationSpec] = Field(min_length=1)
    dependencies: list[str] = Field(default_factory=list)
    required_permissions: list[str] = Field(default_factory=list)
    network_access: str = "none"
    allowed_hosts: list[str] = Field(default_factory=list)
    filesystem_access: str = "none"
    scoped_paths: list[str] = Field(default_factory=list)
    possible_side_effects: list[str] = Field(default_factory=list)
    timeout_seconds: float = Field(default=15.0, gt=0.0, le=120.0)
    max_memory_mb: int = Field(default=256, ge=32, le=2048)
    entrypoint: str = "plugin_main.py"
    tests: list[str] = Field(default_factory=list)
    compatibility: PluginCompatibility = Field(default_factory=PluginCompatibility)
    trust: PluginTrust = Field(default_factory=PluginTrust)

    @field_validator("version")
    @classmethod
    def _check_version(cls, value: str) -> str:
        parse_version(value)
        return value

    @field_validator("category")
    @classmethod
    def _check_category(cls, value: str) -> str:
        if value not in PLUGIN_CATEGORIES:
            raise ValueError(f"category must be one of {PLUGIN_CATEGORIES}")
        return value

    @field_validator("network_access")
    @classmethod
    def _check_network(cls, value: str) -> str:
        if value not in NETWORK_MODES:
            raise ValueError(f"network_access must be one of {NETWORK_MODES}")
        return value

    @field_validator("filesystem_access")
    @classmethod
    def _check_fs(cls, value: str) -> str:
        if value not in FILESYSTEM_MODES:
            raise ValueError(f"filesystem_access must be one of {FILESYSTEM_MODES}")
        return value

    @field_validator("scoped_paths")
    @classmethod
    def _check_scoped_paths(cls, values: list[str]) -> list[str]:
        for item in values:
            cleaned = item.replace("\\", "/").strip("/")
            if not cleaned or ".." in cleaned.split("/") or item.startswith("/"):
                raise ValueError(f"scoped_paths entry '{item}' must be a safe workspace-relative subpath")
        return values


# ------------------------------------------------------- §109 Developer SDK


@dataclass(frozen=True)
class ExtensionError:
    category: str
    message: str
    recoverable: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"category": self.category, "message": self.message, "recoverable": self.recoverable}


class ExtensionContext:
    """Narrow, capability-safe execution context handed to in-process SDK extensions.

    Intentionally holds no reference to ``Database``, ``AutonomyPolicy`` or
    ``ToolRegistry`` so an extension cannot mutate permissions or invoke other
    tools behind the policy engine's back (§109).
    """

    __slots__ = ("_cancelled", "_config", "_errors", "_logs", "_redactor", "_workspace_root")

    def __init__(
        self,
        *,
        workspace_root: Path,
        config: dict[str, Any] | None = None,
        cancelled: Callable[[], bool] | None = None,
        redactor: Redactor | None = None,
    ) -> None:
        self._workspace_root = Path(workspace_root).resolve()
        self._config = MappingProxyType(dict(config or {}))
        self._cancelled = cancelled or (lambda: False)
        self._redactor = redactor or Redactor()
        self._logs: list[dict[str, str]] = []
        self._errors: list[ExtensionError] = []

    @property
    def workspace_root(self) -> Path:
        return self._workspace_root

    @property
    def config(self) -> MappingProxyType[str, Any]:
        return self._config

    def is_cancelled(self) -> bool:
        return bool(self._cancelled())

    def resolve_workspace_path(self, relative_path: str) -> Path:
        cleaned = (relative_path or ".").strip()
        if cleaned.startswith("/") or "\x00" in cleaned:
            raise PermissionError("Absolute paths are outside the extension workspace scope")
        resolved = (self._workspace_root / cleaned).resolve()
        if not resolved.is_relative_to(self._workspace_root):
            raise PermissionError("Path escapes the authorized workspace root")
        return resolved

    def log(self, level: str, message: str) -> None:
        self._logs.append(
            {
                "level": level.lower(),
                "message": self._redactor.scrub_text(message, max_chars=300),
                "logged_at": _iso(),
            }
        )

    def report_error(self, category: str, message: str, *, recoverable: bool = True) -> ExtensionError:
        err = ExtensionError(
            category=self._redactor.scrub_text(category, max_chars=60),
            message=self._redactor.scrub_text(message, max_chars=300),
            recoverable=recoverable,
        )
        self._errors.append(err)
        return err

    def diagnostics(self) -> dict[str, Any]:
        return {
            "logs": list(self._logs),
            "errors": [item.to_dict() for item in self._errors],
        }


ExtensionHandler = Callable[[dict[str, Any], ExtensionContext], dict[str, Any]]


@dataclass(frozen=True)
class SDKExtension:
    manifest: PluginManifest
    handlers: dict[str, ExtensionHandler]
    test_hook: Callable[[Path], bool] | None = None


def validate_json_against_schema(payload: Any, schema: dict[str, Any]) -> list[str]:
    """Lightweight JSON-Schema subset validator for plugin/MCP inputs & outputs."""
    if not isinstance(payload, dict):
        return ["value must be a JSON object"]
    issues: list[str] = []
    required = schema.get("required") or []
    properties = schema.get("properties") or {}
    for req in required:
        if req not in payload:
            issues.append(f"missing required property '{req}'")
    type_map: dict[str, tuple[type, ...]] = {
        "string": (str,),
        "integer": (int,),
        "number": (int, float),
        "boolean": (bool,),
        "array": (list,),
        "object": (dict,),
    }
    for key, value in payload.items():
        spec = properties.get(key)
        if not isinstance(spec, dict):
            if schema.get("additionalProperties") is False:
                issues.append(f"unexpected property '{key}'")
            continue
        expected_type = spec.get("type")
        if expected_type in type_map:
            if expected_type in {"integer", "number"} and isinstance(value, bool):
                issues.append(f"property '{key}' expected {expected_type}, got boolean")
            elif not isinstance(value, type_map[expected_type]):
                issues.append(f"property '{key}' expected {expected_type}")
    return issues


def validate_extension_source_ast(source_code: str) -> list[str]:
    """Static check ensuring plugin code does not import internal NOVA auth/DB modules."""
    try:
        tree = ast.parse(source_code)
    except SyntaxError as exc:
        return [f"syntax error at line {exc.lineno}: {exc.msg}"]
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                for forbidden in FORBIDDEN_EXTENSION_IMPORTS:
                    if alias.name == forbidden or alias.name.startswith(forbidden + "."):
                        violations.append(f"forbidden import '{alias.name}'")
        elif isinstance(node, ast.ImportFrom) and node.module:
            for forbidden in FORBIDDEN_EXTENSION_IMPORTS:
                if node.module == forbidden or node.module.startswith(forbidden + "."):
                    violations.append(f"forbidden import from '{node.module}'")
    return violations


def validate_extension_dev_mode(extension: SDKExtension, workspace_root: Path, *, source_code: str = "") -> dict[str, Any]:
    """§109 Development-mode validator run before an extension may be enabled."""
    issues: list[str] = []
    if extension.manifest.sdk_version.split(".")[0] != SDK_API_VERSION.split(".")[0]:
        issues.append(f"incompatible sdk_version '{extension.manifest.sdk_version}' (expected {SDK_API_VERSION})")
    declared_ops = {op.name for op in extension.manifest.operations}
    missing_handlers = sorted(declared_ops - set(extension.handlers))
    if missing_handlers:
        issues.append(f"missing handlers for operations: {', '.join(missing_handlers)}")
    if source_code:
        issues.extend(validate_extension_source_ast(source_code))
    test_passed: bool | None = None
    if extension.test_hook is not None and not issues:
        try:
            test_passed = bool(extension.test_hook(workspace_root))
        except Exception as exc:
            test_passed = False
            issues.append(f"test_hook raised {type(exc).__name__}: {exc}")
        if test_passed is False and not any("test_hook" in item for item in issues):
            issues.append("extension test_hook returned False")
    return {
        "valid": not issues,
        "plugin": extension.manifest.name,
        "version": extension.manifest.version,
        "sdk_version": extension.manifest.sdk_version,
        "operations": sorted(declared_ops),
        "test_passed": test_passed,
        "issues": issues,
    }


# ----------------------------------------- 4 Built-in §109 Example Extensions


def builtin_sdk_examples() -> tuple[SDKExtension, ...]:
    """Four reference SDK extensions required by §109."""

    def _fs_search(args: dict[str, Any], ctx: ExtensionContext) -> dict[str, Any]:
        needle = str(args.get("query") or "").strip().lower()
        subpath = str(args.get("subpath") or ".")
        root = ctx.resolve_workspace_path(subpath)
        matches: list[dict[str, Any]] = []
        if not needle or not root.exists():
            return {"matches": matches, "count": 0}
        files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
        for file_path in files[:200]:
            if ctx.is_cancelled():
                break
            try:
                text = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for line_no, line in enumerate(text.splitlines(), start=1):
                if needle in line.lower():
                    matches.append(
                        {
                            "path": str(file_path.relative_to(ctx.workspace_root)),
                            "line": line_no,
                            "preview": line.strip()[:160],
                        }
                    )
                    if len(matches) >= 50:
                        return {"matches": matches, "count": len(matches)}
        return {"matches": matches, "count": len(matches)}

    def _repo_inspect(args: dict[str, Any], ctx: ExtensionContext) -> dict[str, Any]:
        root = ctx.resolve_workspace_path(str(args.get("subpath") or "."))
        py_files = 0
        doc_files = 0
        manifests: list[str] = []
        if root.is_dir():
            for path in sorted(root.rglob("*"))[:500]:
                if not path.is_file():
                    continue
                if path.suffix == ".py":
                    py_files += 1
                elif path.suffix in {".md", ".rst", ".txt"}:
                    doc_files += 1
                if path.name in {"pyproject.toml", "requirements.txt", "package.json", "Cargo.toml"}:
                    manifests.append(str(path.relative_to(ctx.workspace_root)))
        return {
            "has_git_dir": (root / ".git").exists(),
            "python_files": py_files,
            "doc_files": doc_files,
            "manifests": manifests,
        }

    def _data_summary(args: dict[str, Any], ctx: ExtensionContext) -> dict[str, Any]:
        import csv

        target = ctx.resolve_workspace_path(str(args.get("path") or ""))
        if not target.is_file():
            ctx.report_error("not_found", "requested data file does not exist")
            return {"rows": 0, "columns": []}
        if target.suffix.lower() == ".json":
            loaded = json.loads(target.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                cols = sorted({k for row in loaded[:50] if isinstance(row, dict) for k in row})
                return {"format": "json_array", "rows": len(loaded), "columns": cols}
            if isinstance(loaded, dict):
                return {"format": "json_object", "rows": 1, "columns": sorted(loaded.keys())}
            return {"format": "json_scalar", "rows": 1, "columns": []}
        with target.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            reader = csv.reader(handle)
            header = next(reader, [])
            row_count = sum(1 for _ in reader)
        return {"format": "csv", "rows": row_count, "columns": list(header)}

    def _api_probe(args: dict[str, Any], ctx: ExtensionContext) -> dict[str, Any]:
        endpoint = str(ctx.config.get("base_url") or args.get("endpoint") or "").strip()
        method = str(args.get("method") or "GET").upper()
        if not endpoint.startswith("https://"):
            ctx.report_error("invalid_endpoint", "only HTTPS endpoints are accepted by configurable_api_probe")
            return {"prepared": False, "endpoint": endpoint, "method": method}
        return {
            "prepared": True,
            "endpoint": endpoint,
            "method": method,
            "live_network_executed": False,
            "note": "Dry-validated request descriptor; live network execution requires explicit network grant.",
        }

    return (
        SDKExtension(
            manifest=PluginManifest(
                name="readonly-fs-search",
                version="0.2.0",
                purpose="Read-only substring search across approved workspace files.",
                category="research",
                operations=[
                    PluginOperationSpec(
                        name="search",
                        description="Search workspace files for a case-insensitive substring.",
                        input_schema={
                            "type": "object",
                            "required": ["query"],
                            "properties": {"query": {"type": "string"}, "subpath": {"type": "string"}},
                        },
                        output_schema={
                            "type": "object",
                            "required": ["matches", "count"],
                            "properties": {"matches": {"type": "array"}, "count": {"type": "integer"}},
                        },
                        autonomy_class="routine",
                    )
                ],
                required_permissions=["workspace.read"],
                filesystem_access="read_workspace",
                trust=PluginTrust(publisher="nova-sdk", trusted=True),
            ),
            handlers={"search": _fs_search},
            test_hook=lambda ws: True,
        ),
        SDKExtension(
            manifest=PluginManifest(
                name="repo-inspector",
                version="0.2.0",
                purpose="Inspect repository layout and dependency manifests without modifying files.",
                category="development",
                operations=[
                    PluginOperationSpec(
                        name="inspect",
                        description="Summarize repository files and dependency manifests.",
                        input_schema={"type": "object", "properties": {"subpath": {"type": "string"}}},
                        output_schema={
                            "type": "object",
                            "required": ["python_files", "manifests"],
                            "properties": {
                                "has_git_dir": {"type": "boolean"},
                                "python_files": {"type": "integer"},
                                "doc_files": {"type": "integer"},
                                "manifests": {"type": "array"},
                            },
                        },
                        autonomy_class="routine",
                    )
                ],
                required_permissions=["workspace.read"],
                filesystem_access="read_workspace",
                trust=PluginTrust(publisher="nova-sdk", trusted=True),
            ),
            handlers={"inspect": _repo_inspect},
            test_hook=lambda ws: True,
        ),
        SDKExtension(
            manifest=PluginManifest(
                name="structured-data-helper",
                version="0.2.0",
                purpose="Inspect CSV and JSON schemas and row counts within the workspace.",
                category="data_analysis",
                operations=[
                    PluginOperationSpec(
                        name="summarize",
                        description="Return format, row count and column names for a CSV or JSON file.",
                        input_schema={
                            "type": "object",
                            "required": ["path"],
                            "properties": {"path": {"type": "string"}},
                        },
                        output_schema={
                            "type": "object",
                            "required": ["rows", "columns"],
                            "properties": {
                                "format": {"type": "string"},
                                "rows": {"type": "integer"},
                                "columns": {"type": "array"},
                            },
                        },
                        autonomy_class="routine",
                    )
                ],
                required_permissions=["workspace.read"],
                filesystem_access="read_workspace",
                trust=PluginTrust(publisher="nova-sdk", trusted=True),
            ),
            handlers={"summarize": _data_summary},
            test_hook=lambda ws: True,
        ),
        SDKExtension(
            manifest=PluginManifest(
                name="configurable-api-probe",
                version="0.2.0",
                purpose="Validate and prepare HTTPS API requests using scoped plugin configuration.",
                category="external_integration",
                operations=[
                    PluginOperationSpec(
                        name="prepare_request",
                        description="Validate an HTTPS endpoint and prepare a bounded request descriptor.",
                        input_schema={
                            "type": "object",
                            "properties": {"endpoint": {"type": "string"}, "method": {"type": "string"}},
                        },
                        output_schema={
                            "type": "object",
                            "required": ["prepared", "endpoint", "method"],
                            "properties": {
                                "prepared": {"type": "boolean"},
                                "endpoint": {"type": "string"},
                                "method": {"type": "string"},
                            },
                        },
                        autonomy_class="approval_required",
                    )
                ],
                required_permissions=["network.https_allowlist"],
                network_access="allowlist",
                allowed_hosts=["api.github.com"],
                trust=PluginTrust(publisher="nova-sdk", trusted=True),
            ),
            handlers={"prepare_request": _api_probe},
            test_hook=lambda ws: True,
        ),
    )


# ------------------------------------------------------- §92 Plugin Manager


@dataclass
class InstalledPlugin:
    manifest: PluginManifest
    install_dir: Path | None
    enabled: bool = False
    granted_permissions: tuple[str, ...] = ()
    config: dict[str, Any] = field(default_factory=dict)
    installed_at: str = field(default_factory=_iso)
    last_diagnostic: dict[str, Any] = field(default_factory=dict)
    sdk_extension: SDKExtension | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.manifest.name,
            "version": self.manifest.version,
            "purpose": self.manifest.purpose,
            "category": self.manifest.category,
            "enabled": self.enabled,
            "required_permissions": list(self.manifest.required_permissions),
            "granted_permissions": list(self.granted_permissions),
            "network_access": self.manifest.network_access,
            "allowed_hosts": list(self.manifest.allowed_hosts),
            "filesystem_access": self.manifest.filesystem_access,
            "scoped_paths": list(self.manifest.scoped_paths),
            "possible_side_effects": list(self.manifest.possible_side_effects),
            "timeout_seconds": self.manifest.timeout_seconds,
            "max_memory_mb": self.manifest.max_memory_mb,
            "operations": [op.model_dump() for op in self.manifest.operations],
            "trust": self.manifest.trust.model_dump(),
            "compatibility": self.manifest.compatibility.model_dump(),
            "installed_at": self.installed_at,
            "kind": "sdk_in_process" if self.sdk_extension is not None else "sandboxed_subprocess",
            "last_diagnostic": dict(self.last_diagnostic),
        }


@dataclass
class PluginManager:
    """Local plugin lifecycle manager with permission scoping & sandboxed candidates."""

    plugins_dir: Path
    workspace_root: Path
    sandbox: Sandbox = field(default_factory=Sandbox)
    redactor: Redactor = field(default_factory=Redactor)
    _plugins: dict[str, InstalledPlugin] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        self.plugins_dir = Path(self.plugins_dir)
        self.workspace_root = Path(self.workspace_root)
        (self.plugins_dir / "installed").mkdir(parents=True, exist_ok=True)
        (self.plugins_dir / "candidates").mkdir(parents=True, exist_ok=True)

    @staticmethod
    def check_compatibility(manifest: PluginManifest) -> list[str]:
        issues: list[str] = []
        compat = manifest.compatibility
        host = platform.system().lower()
        if compat.platforms and host not in [p.lower() for p in compat.platforms]:
            issues.append(f"plugin requires platform {compat.platforms}, host is '{host}'")
        if parse_version(__version__)[:3] < parse_version(compat.min_nova_version)[:3]:
            issues.append(f"plugin requires NOVA >= {compat.min_nova_version} (running {__version__})")
        if compat.max_nova_version and parse_version(__version__)[:3] > parse_version(compat.max_nova_version)[:3]:
            issues.append(f"plugin supports NOVA <= {compat.max_nova_version}")
        py_parts = [int(x) for x in compat.min_python.split(".")[:2] if x.isdigit()]
        if len(py_parts) == 2 and (sys.version_info.major, sys.version_info.minor) < (py_parts[0], py_parts[1]):
            issues.append(f"plugin requires Python >= {compat.min_python}")
        for dep in manifest.dependencies:
            mod_name = dep.split(">=")[0].split("==")[0].strip().replace("-", "_")
            if mod_name and __import__("importlib.util").util.find_spec(mod_name) is None:
                issues.append(f"missing Python dependency '{dep}'")
        return issues

    def register_sdk_extension(self, extension: SDKExtension, *, auto_enable: bool = False, granted_permissions: tuple[str, ...] = ()) -> dict[str, Any]:
        validation = validate_extension_dev_mode(extension, self.workspace_root)
        if not validation["valid"]:
            return {"installed": False, "issues": validation["issues"]}
        compat_issues = self.check_compatibility(extension.manifest)
        if compat_issues:
            return {"installed": False, "issues": compat_issues}
        record = InstalledPlugin(
            manifest=extension.manifest,
            install_dir=None,
            enabled=False,
            granted_permissions=(),
            sdk_extension=extension,
        )
        self._plugins[extension.manifest.name] = record
        if auto_enable:
            return self.enable(extension.manifest.name, granted_permissions=granted_permissions)
        return {"installed": True, "plugin": record.to_dict()}

    def install_from_directory(self, source_dir: Path, *, expected_sha256: str = "") -> dict[str, Any]:
        """Validate and install a subprocess plugin in disabled state with zero granted permissions."""
        src = Path(source_dir)
        manifest_path = src / "plugin.json"
        if not manifest_path.is_file():
            return {"installed": False, "reason": "plugin.json is missing"}
        try:
            manifest = PluginManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
        except ValidationError as exc:
            return {"installed": False, "reason": f"invalid manifest: {exc.errors()[:3]}"}

        entry_path = (src / manifest.entrypoint).resolve()
        if not entry_path.is_relative_to(src.resolve()) or not entry_path.is_file():
            return {"installed": False, "reason": f"entrypoint '{manifest.entrypoint}' is missing or escapes plugin directory"}

        ast_issues = validate_extension_source_ast(entry_path.read_text(encoding="utf-8", errors="replace"))
        if ast_issues:
            return {"installed": False, "reason": "extension boundary violation: " + "; ".join(ast_issues)}

        digest = hashlib.sha256(entry_path.read_bytes()).hexdigest()
        declared_sha = expected_sha256 or manifest.trust.sha256
        if declared_sha and digest.lower() != declared_sha.strip().lower():
            return {"installed": False, "reason": "entrypoint SHA-256 checksum mismatch"}

        compat_issues = self.check_compatibility(manifest)
        if compat_issues:
            return {"installed": False, "reason": "; ".join(compat_issues)}

        dest = self.plugins_dir / "installed" / manifest.name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(src, dest)

        # §92: Installing a plugin NEVER grants permissions or enables it automatically.
        record = InstalledPlugin(manifest=manifest, install_dir=dest, enabled=False, granted_permissions=())
        self._plugins[manifest.name] = record
        return {"installed": True, "plugin": record.to_dict(), "checksum_sha256": digest}

    def enable(self, name: str, *, granted_permissions: tuple[str, ...] | list[str]) -> dict[str, Any]:
        plugin = self._plugins.get(name)
        if plugin is None:
            return {"enabled": False, "reason": f"plugin '{name}' is not installed"}
        granted = set(granted_permissions)
        missing = sorted(set(plugin.manifest.required_permissions) - granted)
        if missing:
            return {
                "enabled": False,
                "plugin": name,
                "reason": f"required permissions were not granted: {', '.join(missing)}",
                "missing_permissions": missing,
            }
        plugin.granted_permissions = tuple(sorted(granted))
        plugin.enabled = True
        return {"enabled": True, "plugin": plugin.to_dict()}

    def disable(self, name: str) -> bool:
        plugin = self._plugins.get(name)
        if plugin is None:
            return False
        plugin.enabled = False
        plugin.granted_permissions = ()
        return True

    def configure(self, name: str, settings: dict[str, Any]) -> dict[str, Any]:
        plugin = self._plugins.get(name)
        if plugin is None:
            return {"configured": False, "reason": f"plugin '{name}' is not installed"}
        plugin.config = dict(settings)
        return {"configured": True, "plugin": name, "keys": sorted(plugin.config)}

    def remove(self, name: str) -> bool:
        plugin = self._plugins.pop(name, None)
        if plugin is None:
            return False
        if plugin.install_dir is not None and plugin.install_dir.exists():
            shutil.rmtree(plugin.install_dir, ignore_errors=True)
        return True

    def update_plugin(self, name: str, new_source_dir: Path) -> dict[str, Any]:
        existing = self._plugins.get(name)
        if existing is None:
            return {"updated": False, "reason": f"plugin '{name}' is not installed"}
        previous_permissions = existing.granted_permissions
        was_enabled = existing.enabled
        backup_dir: Path | None = None
        if existing.install_dir is not None and existing.install_dir.exists():
            backup_dir = self.plugins_dir / "backups" / f"{name}-{existing.manifest.version}"
            if backup_dir.exists():
                shutil.rmtree(backup_dir)
            backup_dir.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(existing.install_dir, backup_dir)

        installed = self.install_from_directory(new_source_dir)
        if not installed.get("installed"):
            if backup_dir is not None and backup_dir.exists():
                self.install_from_directory(backup_dir)
                if was_enabled:
                    self.enable(name, granted_permissions=previous_permissions)
            return {"updated": False, "rolled_back": True, "reason": installed.get("reason", "install failed")}

        # New permissions added in an update are NOT auto-granted!
        updated_plugin = self._plugins[name]
        if was_enabled and set(updated_plugin.manifest.required_permissions).issubset(set(previous_permissions)):
            self.enable(name, granted_permissions=previous_permissions)
        return {"updated": True, "plugin": updated_plugin.to_dict()}

    def execute(self, name: str, operation: str, arguments: dict[str, Any], *, cancelled: Callable[[], bool] | None = None) -> dict[str, Any]:
        plugin = self._plugins.get(name)
        if plugin is None:
            return {"status": "error", "reason": f"plugin '{name}' is not installed"}
        if not plugin.enabled:
            return {"status": "denied", "reason": f"plugin '{name}' is disabled"}
        missing = sorted(set(plugin.manifest.required_permissions) - set(plugin.granted_permissions))
        if missing:
            return {"status": "denied", "reason": f"missing permissions: {', '.join(missing)}"}

        op_spec = next((op for op in plugin.manifest.operations if op.name == operation), None)
        if op_spec is None:
            return {"status": "error", "reason": f"operation '{operation}' is not declared by plugin '{name}'"}

        input_issues = validate_json_against_schema(arguments, op_spec.input_schema)
        if input_issues:
            return {"status": "error", "reason": "invalid plugin input: " + "; ".join(input_issues)}

        if plugin.sdk_extension is not None:
            ctx = ExtensionContext(
                workspace_root=self.workspace_root,
                config=plugin.config,
                cancelled=cancelled,
                redactor=self.redactor,
            )
            handler = plugin.sdk_extension.handlers[operation]
            try:
                output = handler(arguments, ctx)
            except PermissionError as exc:
                return {"status": "denied", "reason": str(exc), "diagnostics": ctx.diagnostics()}
            except Exception as exc:
                return {"status": "error", "reason": f"{type(exc).__name__}: {exc}", "diagnostics": ctx.diagnostics()}
            out_issues = validate_json_against_schema(output, op_spec.output_schema)
            if out_issues:
                return {"status": "error", "reason": "plugin returned invalid output schema: " + "; ".join(out_issues)}
            return {"status": "success", "data": output, "diagnostics": ctx.diagnostics()}

        # Subprocess plugin: execute inside Sandbox according to declared access & trust.
        assert plugin.install_dir is not None
        entrypoint = plugin.install_dir / plugin.manifest.entrypoint
        writable_roots: list[str] = []
        if plugin.manifest.filesystem_access == "scoped_write":
            for rel in plugin.manifest.scoped_paths:
                scoped = (self.workspace_root / rel).resolve()
                scoped.mkdir(parents=True, exist_ok=True)
                writable_roots.append(str(scoped))
        network_allowed = (
            plugin.manifest.network_access == "allowlist"
            and "network.https_allowlist" in plugin.granted_permissions
        )
        risk = (
            RISK_UNTRUSTED_CODE
            if not plugin.manifest.trust.trusted
            else (RISK_SCOPED_WRITE if writable_roots else RISK_PURE)
        )
        sbx_policy = SandboxPolicy(
            writable_roots=tuple(writable_roots),
            network=network_allowed,
            timeout_seconds=plugin.manifest.timeout_seconds,
            cwd=str(self.workspace_root.resolve()) if self.workspace_root.exists() else "",
        )
        request_json = json.dumps({"operation": operation, "arguments": arguments, "config": plugin.config})
        run = self.sandbox.run([sys.executable, str(entrypoint)], risk=risk, policy=sbx_policy, stdin_text=request_json)
        plugin.last_diagnostic = {
            "ran_at": _iso(),
            "status": run.status,
            "mechanism": run.mechanism,
            "exit_code": run.exit_code,
        }
        if run.status != STATUS_COMPLETED or run.exit_code != 0:
            return {
                "status": "error",
                "reason": run.refused_reason or f"sandboxed plugin exited with status={run.status} code={run.exit_code}",
                "sandbox_mechanism": run.mechanism,
                "stderr": self.redactor.scrub_text(run.stderr, max_chars=300),
            }
        try:
            parsed = json.loads(run.stdout.strip() or "{}")
        except ValueError:
            return {"status": "error", "reason": "plugin stdout was not valid JSON"}
        out_issues = validate_json_against_schema(parsed, op_spec.output_schema)
        if out_issues:
            return {"status": "error", "reason": "plugin output failed schema validation: " + "; ".join(out_issues)}
        return {"status": "success", "data": parsed, "sandbox_mechanism": run.mechanism}

    # -- Candidate plugin staging (§92)

    def stage_candidate(self, manifest_dict: dict[str, Any], entrypoint_code: str, *, test_code: str = "") -> dict[str, Any]:
        """Create a candidate plugin in a separate staging workspace and inspect + test it in isolation."""
        try:
            manifest = PluginManifest.model_validate(manifest_dict)
        except ValidationError as exc:
            return {"staged": False, "passed_checks": False, "issues": [str(item["msg"]) for item in exc.errors()[:5]]}

        ast_issues = validate_extension_source_ast(entrypoint_code)
        if ast_issues:
            return {"staged": False, "passed_checks": False, "issues": ast_issues}

        cand_dir = self.plugins_dir / "candidates" / f"{manifest.name}-{manifest.version}"
        if cand_dir.exists():
            shutil.rmtree(cand_dir)
        cand_dir.mkdir(parents=True, exist_ok=True)
        (cand_dir / "plugin.json").write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
        (cand_dir / manifest.entrypoint).write_text(entrypoint_code, encoding="utf-8")

        test_passed = True
        test_detail = "no candidate test script supplied"
        if test_code.strip():
            test_file = cand_dir / "test_candidate.py"
            test_file.write_text(test_code, encoding="utf-8")
            scratch = cand_dir / "scratch"
            scratch.mkdir(exist_ok=True)
            res = self.sandbox.run(
                [sys.executable, str(test_file)],
                risk=RISK_UNTRUSTED_CODE,
                policy=SandboxPolicy(writable_roots=(str(scratch.resolve()),), network=False, timeout_seconds=15.0),
            )
            test_passed = res.status == STATUS_COMPLETED and res.exit_code == 0
            test_detail = f"sandbox({res.mechanism}) status={res.status} exit={res.exit_code}"

        permission_inspection = {
            "required_permissions": list(manifest.required_permissions),
            "network_access": manifest.network_access,
            "allowed_hosts": list(manifest.allowed_hosts),
            "filesystem_access": manifest.filesystem_access,
            "scoped_paths": list(manifest.scoped_paths),
            "side_effects": list(manifest.possible_side_effects),
        }
        return {
            "staged": True,
            "candidate_dir": str(cand_dir),
            "passed_checks": test_passed,
            "test_detail": test_detail,
            "permission_inspection": permission_inspection,
        }

    def promote_candidate(self, candidate_dir: Path, *, checks_passed: bool, operator_approved: bool) -> dict[str, Any]:
        if not checks_passed:
            return {"promoted": False, "reason": "candidate plugin failed validation or sandbox tests"}
        if not operator_approved:
            return {"promoted": False, "reason": "operator approval is required after inspecting candidate permissions"}
        installed = self.install_from_directory(candidate_dir)
        return {"promoted": bool(installed.get("installed")), **installed}

    def register_into_tool_registry(self, registry: ToolRegistry) -> list[str]:
        """Expose enabled plugin operations through NOVA's ToolRegistry so AutonomyPolicy gates them."""
        registered: list[str] = []
        for plugin in self._plugins.values():
            if not plugin.enabled:
                continue
            for op in plugin.manifest.operations:
                tool_name = f"plugin.{plugin.manifest.name}.{op.name}"
                if registry.get(tool_name) is not None:
                    continue

                class _DynamicArgs(BaseModel):
                    model_config = {"extra": "allow"}

                def _make_handler(pname: str, op_name: str):
                    async def _handler(parsed: BaseModel, _approved: bool) -> ToolOutcome:
                        result = self.execute(pname, op_name, parsed.model_dump())
                        if result["status"] == "success":
                            return ToolOutcome("success", f"Plugin '{pname}.{op_name}' completed.", result.get("data"))
                        return ToolOutcome(result["status"], result.get("reason", "Plugin execution failed."), result)

                    return _handler

                registry.register(
                    ToolDefinition(
                        name=tool_name,
                        description=f"[{plugin.manifest.name}] {op.description}",
                        parameters=op.input_schema,
                        input_model=_DynamicArgs,
                        handler=_make_handler(plugin.manifest.name, op.name),
                        permission=",".join(plugin.manifest.required_permissions) or "plugin.execute",
                        available=True,
                        category=plugin.manifest.category,
                        autonomy_class=op.autonomy_class,
                    )
                )
                registered.append(tool_name)
        return registered

    def list_plugins(self) -> list[dict[str, Any]]:
        return [item.to_dict() for item in self._plugins.values()]


__all__ = [
    "FILESYSTEM_MODES",
    "FORBIDDEN_EXTENSION_IMPORTS",
    "NETWORK_MODES",
    "PLUGIN_CATEGORIES",
    "PLUGIN_SCHEMA_VERSION",
    "SDK_API_VERSION",
    "ExtensionContext",
    "ExtensionError",
    "InstalledPlugin",
    "PluginCompatibility",
    "PluginManager",
    "PluginManifest",
    "PluginOperationSpec",
    "PluginTrust",
    "SDKExtension",
    "builtin_sdk_examples",
    "validate_extension_dev_mode",
    "validate_extension_source_ast",
    "validate_json_against_schema",
]
