"""Workspace-only file tools with path traversal, symlink, size, and overwrite safeguards."""
from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from nova.config import Settings
from nova.tools.registry import ToolDefinition, ToolOutcome


class ListFilesInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(default=".", max_length=500, description="Workspace-relative directory")


class ReadFileInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1, max_length=500, description="Workspace-relative text file")


class WriteFileInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1, max_length=500, description="Workspace-relative output file")
    content: str = Field(max_length=1_000_000, description="UTF-8 text content")


class SearchFilesInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=300, description="Text to find")
    path: str = Field(default=".", max_length=500, description="Workspace-relative directory")
    max_results: int = Field(default=20, ge=1, le=50)


_SENSITIVE_WORKSPACE_NAMES = {
    ".ssh", ".gnupg", ".aws", ".kube", ".netrc", ".npmrc", ".pypirc", ".nova_backups", "credentials",
    "secrets", "keyrings", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "token.json",
}


def _sensitive_workspace_name(name: str) -> bool:
    lowered = name.casefold()
    return (
        lowered in _SENSITIVE_WORKSPACE_NAMES
        or lowered == ".env"
        or lowered.startswith(".env.")
        or lowered in {"credentials.json", "service-account.json", "private.key"}
    )


def _safe_path(root: Path, raw: str) -> Path:
    if not isinstance(raw, str) or "\x00" in raw:
        raise ValueError("Invalid path")
    normalized = raw.replace("\\", "/")
    pure = PurePosixPath(normalized)
    windows = PureWindowsPath(raw)
    if pure.is_absolute() or windows.is_absolute() or windows.drive:
        raise ValueError("Absolute paths are not allowed")
    if any(part in {"..", ""} for part in normalized.split("/") if part != "."):
        raise ValueError("Path traversal is not allowed")
    rel = Path(*[part for part in pure.parts if part not in {"", "."}])
    if any(_sensitive_workspace_name(part) for part in rel.parts):
        raise ValueError("Credential and private-key paths are excluded from agent workspace access")
    candidate = root / rel
    current = root
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("Symbolic links are not allowed in the workspace")
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("Path is outside the approved workspace") from exc
    return resolved


def _relative(root: Path, path: Path) -> str:
    return "." if path == root else path.relative_to(root).as_posix()


def build_workspace_tools(settings: Settings, root_provider: Callable[[], str | Path] | None = None) -> list[ToolDefinition]:
    default_root = settings.workspace_dir.resolve()
    default_root.mkdir(parents=True, exist_ok=True)

    def current_root() -> Path:
        if root_provider is None:
            return default_root
        try:
            candidate = Path(root_provider()).expanduser().resolve(strict=True)
            return candidate if candidate.is_dir() else default_root
        except (OSError, RuntimeError, ValueError):
            return default_root

    async def list_files(args: BaseModel, _approved: bool) -> ToolOutcome:
        root = current_root()
        try:
            folder = _safe_path(root, args.path)  # type: ignore[attr-defined]
            if not folder.exists() or not folder.is_dir():
                return ToolOutcome("error", "That workspace directory does not exist.")
            entries = []
            for item in sorted(folder.iterdir(), key=lambda p: (not p.is_dir(), p.name.casefold())):
                if item.name == ".nova_backups" or item.name.startswith(".nova-tmp-") or _sensitive_workspace_name(item.name):
                    continue
                if item.is_symlink():
                    continue
                try:
                    entries.append({
                        "name": item.name,
                        "path": _relative(root, item),
                        "type": "directory" if item.is_dir() else "file",
                        "size_bytes": item.stat().st_size if item.is_file() else None,
                    })
                except OSError:
                    continue
                if len(entries) >= 200:
                    break
            return ToolOutcome("success", f"Listed {len(entries)} workspace entries.", {"directory": _relative(root, folder), "entries": entries})
        except ValueError as exc:
            return ToolOutcome("denied", f"Path rejected: {exc}.")
        except OSError:
            return ToolOutcome("error", "Could not list that workspace directory.")

    async def read_file(args: BaseModel, _approved: bool) -> ToolOutcome:
        root = current_root()
        try:
            path = _safe_path(root, args.path)  # type: ignore[attr-defined]
            if not path.exists() or not path.is_file():
                return ToolOutcome("error", "That workspace file does not exist or is not a regular file.")
            size = path.stat().st_size
            if size > settings.max_file_bytes:
                return ToolOutcome("error", f"File is {size} bytes; configured limit is {settings.max_file_bytes} bytes.")
            raw = path.read_bytes()
            try:
                content = raw.decode("utf-8")
            except UnicodeDecodeError:
                return ToolOutcome("error", "This tool reads UTF-8 text files only; binary file content was not returned.")
            return ToolOutcome("success", f"Read {_relative(root, path)} ({size} bytes).", {"path": _relative(root, path), "content": content, "size_bytes": size})
        except ValueError as exc:
            return ToolOutcome("denied", f"Path rejected: {exc}.")
        except OSError:
            return ToolOutcome("error", "Could not read that workspace file.")

    async def write_file(args: BaseModel, approved: bool) -> ToolOutcome:
        root = current_root()
        try:
            path = _safe_path(root, args.path)  # type: ignore[attr-defined]
            content = args.content  # type: ignore[attr-defined]
            encoded = content.encode("utf-8")
            if len(encoded) > settings.max_file_bytes:
                return ToolOutcome("error", f"Output is larger than the configured {settings.max_file_bytes}-byte file limit.")
            if path == root:
                return ToolOutcome("denied", "A filename is required; the workspace root cannot be replaced.")
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() and not path.is_file():
                return ToolOutcome("denied", "The target exists and is not a regular file.")
            if path.exists() and path.stat().st_size > settings.max_file_bytes:
                return ToolOutcome("error", "The existing file is larger than NOVA's safe backup limit; it was left unchanged.")
            if path.exists() and path.read_bytes() == encoded:
                digest = hashlib.sha256(encoded).hexdigest()
                return ToolOutcome("success", f"{_relative(root, path)} already contains the requested content; no write was performed.", {"path": _relative(root, path), "size_bytes": len(encoded), "sha256": digest, "backup": None, "unchanged": True})
            if path.exists() and not approved:
                return ToolOutcome(
                    "approval_required",
                    f"The file {_relative(root, path)} already exists. Replacing it requires approval; an in-workspace backup will be made first.",
                    {"path": _relative(root, path), "existing_size_bytes": path.stat().st_size},
                    {"operation": "overwrite_file", "path": _relative(root, path)},
                )
            if not path.exists():
                # Exclusive creation prevents a race from silently replacing a file.
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    with os.fdopen(descriptor, "wb") as stream:
                        stream.write(encoded)
                        stream.flush()
                        os.fsync(stream.fileno())
                except Exception:
                    try:
                        path.unlink(missing_ok=True)
                    except OSError:
                        pass
                    raise
                backup = None
            else:
                backup_dir = root / ".nova_backups"
                if backup_dir.is_symlink():
                    return ToolOutcome("denied", "The workspace backup directory is unsafe; overwrite was blocked.")
                backup_dir.mkdir(exist_ok=True)
                if len(list(backup_dir.glob("*.bak"))) >= 50:
                    return ToolOutcome("error", "The 50-backup safety limit was reached; archive backups manually before replacing another file.")
                stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
                backup = backup_dir / f"{stamp}-{uuid.uuid4().hex[:8]}-{path.name}.bak"
                shutil.copy2(path, backup)
                temp_path: Path | None = None
                try:
                    with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent, prefix=".nova-tmp-", delete=False) as stream:
                        temp_path = Path(stream.name)
                        stream.write(encoded)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temp_path, path)
                finally:
                    if temp_path is not None:
                        temp_path.unlink(missing_ok=True)
            digest = hashlib.sha256(encoded).hexdigest()
            return ToolOutcome(
                "success",
                f"Saved and verified {_relative(root, path)} ({len(encoded)} bytes; SHA-256 {digest[:16]}…).",
                {"path": _relative(root, path), "size_bytes": len(encoded), "sha256": digest, "backup": _relative(root, backup) if backup else None},
            )
        except FileExistsError:
            return ToolOutcome("approval_required", "The target was created concurrently. Review it before any replacement.", {"path": args.path}, {"operation": "overwrite_file", "path": args.path})  # type: ignore[attr-defined]
        except ValueError as exc:
            return ToolOutcome("denied", f"Path rejected: {exc}.")
        except OSError:
            return ToolOutcome("error", "Could not safely write that workspace file.")

    async def search_files(args: BaseModel, _approved: bool) -> ToolOutcome:
        root = current_root()
        query = args.query  # type: ignore[attr-defined]
        max_results = args.max_results  # type: ignore[attr-defined]
        try:
            folder = _safe_path(root, args.path)  # type: ignore[attr-defined]
            if not folder.exists() or not folder.is_dir():
                return ToolOutcome("error", "That workspace directory does not exist.")
            needle = query.casefold()
            hits: list[dict[str, Any]] = []
            inspected = 0
            for current, dirs, files in os.walk(folder, followlinks=False):
                dirs[:] = [name for name in dirs if name != ".nova_backups" and not name.startswith(".")]
                for filename in files:
                    file_path = Path(current) / filename
                    if file_path.is_symlink() or filename.startswith(".nova-tmp-") or _sensitive_workspace_name(filename):
                        continue
                    inspected += 1
                    if inspected > 500:
                        break
                    try:
                        if file_path.stat().st_size > settings.max_file_bytes:
                            continue
                        text = file_path.read_text(encoding="utf-8")
                    except (OSError, UnicodeDecodeError):
                        continue
                    for line_number, line in enumerate(text.splitlines(), start=1):
                        if needle in line.casefold():
                            hits.append({"path": _relative(root, file_path), "line": line_number, "text": line[:500]})
                            if len(hits) >= max_results:
                                break
                    if len(hits) >= max_results or inspected > 500:
                        break
                if len(hits) >= max_results or inspected > 500:
                    break
            return ToolOutcome("success", f"Found {len(hits)} matching lines in {inspected} files scanned.", {"query": query, "matches": hits, "files_scanned": inspected, "scan_limit_reached": inspected > 500})
        except ValueError as exc:
            return ToolOutcome("denied", f"Path rejected: {exc}.")
        except OSError:
            return ToolOutcome("error", "Could not search that workspace directory.")

    return [
        ToolDefinition(
            name="workspace.list_files",
            description="List files and directories only inside NOVA's currently selected workspace. Never accesses arbitrary system paths.",
            parameters={"type": "object", "properties": {"path": {"type": "string", "default": ".", "maxLength": 500}}, "additionalProperties": False},
            input_model=ListFilesInput, handler=list_files, permission="read approved NOVA workspace", category="files", autonomy_class="routine",
        ),
        ToolDefinition(
            name="workspace.read_file",
            description="Read a bounded UTF-8 text file inside NOVA's currently selected workspace.",
            parameters={"type": "object", "properties": {"path": {"type": "string", "minLength": 1, "maxLength": 500}}, "required": ["path"], "additionalProperties": False},
            input_model=ReadFileInput, handler=read_file, permission="read approved NOVA workspace; bounded size", category="files", autonomy_class="routine",
        ),
        ToolDefinition(
            name="workspace.write_file",
            description="Create a UTF-8 text file inside NOVA's currently selected workspace. Existing files cannot be replaced without explicit user approval; approved replacements are backed up first.",
            parameters={"type": "object", "properties": {"path": {"type": "string", "minLength": 1, "maxLength": 500}, "content": {"type": "string", "maxLength": 1000000}}, "required": ["path", "content"], "additionalProperties": False},
            input_model=WriteFileInput, handler=write_file, permission="create workspace files; overwrite requires approval and backup", category="files", autonomy_class="routine",
        ),
        ToolDefinition(
            name="workspace.search_files",
            description="Search text in bounded UTF-8 files inside the currently selected workspace. Search is limited to 500 files per call.",
            parameters={"type": "object", "properties": {"query": {"type": "string", "minLength": 1, "maxLength": 300}, "path": {"type": "string", "default": ".", "maxLength": 500}, "max_results": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20}}, "required": ["query"], "additionalProperties": False},
            input_model=SearchFilesInput, handler=search_files, permission="read approved NOVA workspace; bounded search", category="files", autonomy_class="routine",
        ),
    ]
