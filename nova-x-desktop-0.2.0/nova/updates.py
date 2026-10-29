"""§104 Application updates & version management, §106 Offline & degraded mode,
and §112 Release channel discipline.

Safety invariants:

* Remote update scripts are never executed (``REMOTE_SCRIPT_EXECUTION = False``).
* An AI-proposed build cannot replace a working installation on its own; any
  candidate must pass integrity, compatibility and launch checks in staging and
  receive explicit operator confirmation.
* Backups use SQLite's online ``backup()`` API plus exported settings so user
  settings and data survive upgrades and failed candidates roll back cleanly.
* While offline or when the provider is unreachable, NOVA reports the exact
  degraded capabilities, never fabricates model responses or internet research,
  never auto-downloads large local models, and revalidates queued tasks'
  assumptions and permissions before resuming them.
"""
from __future__ import annotations

import hashlib
import json
import platform
import shutil
import sqlite3
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nova import __version__
from nova.db import Database
from nova.resources import ResourceManager

CHANNEL_STABLE = "stable"
CHANNEL_CANDIDATE = "candidate"
CHANNEL_DEVELOPMENT = "development"
RELEASE_CHANNELS = (CHANNEL_STABLE, CHANNEL_CANDIDATE, CHANNEL_DEVELOPMENT)

MODE_ONLINE = "online"
MODE_PROVIDER_UNAVAILABLE = "provider_unavailable"
MODE_OFFLINE = "offline"
OPERATION_MODES = (MODE_ONLINE, MODE_PROVIDER_UNAVAILABLE, MODE_OFFLINE)

REMOTE_SCRIPT_EXECUTION = False
AUTO_MODEL_DOWNLOAD_PERMITTED = False

OFFLINE_CAPABILITIES: tuple[str, ...] = (
    "open_native_desktop_application",
    "view_local_conversation_and_task_history",
    "access_saved_project_notes",
    "search_indexed_local_documents_fts",
    "run_authorized_local_tools",
    "inspect_installed_software_and_capabilities",
    "manage_saved_workflows",
    "view_cached_and_diagnostic_reports",
    "execute_deterministic_utilities",
    "edit_local_code_and_documents",
)

ONLINE_ONLY_CAPABILITIES: tuple[str, ...] = (
    "cloud_frontier_model_inference",
    "multi_model_cloud_fusion",
    "live_external_web_research",
    "remote_mcp_connectors",
)


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def parse_version(raw: str) -> tuple[int, int, int, str]:
    """Parse ``MAJOR.MINOR.PATCH[-prerelease]`` into a comparable tuple."""
    cleaned = (raw or "").strip().lstrip("v")
    core, _, suffix = cleaned.partition("-")
    parts = core.split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        raise ValueError(f"Invalid semantic version: {raw!r}")
    return int(parts[0]), int(parts[1]), int(parts[2]), suffix


def is_newer_version(candidate: str, current: str) -> bool:
    cand_maj, cand_min, cand_pat, cand_suf = parse_version(candidate)
    cur_maj, cur_min, cur_pat, cur_suf = parse_version(current)
    if (cand_maj, cand_min, cand_pat) != (cur_maj, cur_min, cur_pat):
        return (cand_maj, cand_min, cand_pat) > (cur_maj, cur_min, cur_pat)
    # A clean release (no suffix) is newer than a pre-release of the same triple.
    return bool(cur_suf and not cand_suf)


@dataclass(frozen=True)
class ReleaseDescriptor:
    version: str
    channel: str = CHANNEL_STABLE
    sha256: str = ""
    release_notes: str = ""
    min_python: str = "3.11"
    platforms: tuple[str, ...] = ("linux",)
    artifact_name: str = ""
    signed: bool = False
    signature_ref: str = ""
    origin: str = "trusted_manifest"
    published_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "channel": self.channel,
            "sha256": self.sha256,
            "release_notes": self.release_notes,
            "min_python": self.min_python,
            "platforms": list(self.platforms),
            "artifact_name": self.artifact_name,
            "signed": self.signed,
            "signature_ref": self.signature_ref,
            "origin": self.origin,
            "published_at": self.published_at,
        }


@dataclass(frozen=True)
class BackupRecord:
    backup_id: str
    created_at: str
    from_version: str
    db_backup_path: str
    settings_backup_path: str
    preserved_keys: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "backup_id": self.backup_id,
            "created_at": self.created_at,
            "from_version": self.from_version,
            "db_backup_path": self.db_backup_path,
            "settings_backup_path": self.settings_backup_path,
            "preserved_keys": list(self.preserved_keys),
        }


@dataclass
class UpdateManager:
    """§104 Trusted update checking, backup/restore, staging and version history."""

    db: Database
    staging_dir: Path
    current_version: str = __version__
    channel: str = CHANNEL_STABLE
    trusted_sources: tuple[str, ...] = ()
    _history: list[dict[str, Any]] = field(default_factory=list, init=False)
    _last_check: dict[str, Any] | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        if self.channel not in RELEASE_CHANNELS:
            raise ValueError(f"Unknown release channel: {self.channel}")
        self.staging_dir = Path(self.staging_dir)
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        self._load_history()
        if not self._history:
            self._append_history("installed", self.current_version, "initial version recorded")

    def _history_path(self) -> Path:
        return self.staging_dir / "version_history.json"

    def _load_history(self) -> None:
        path = self._history_path()
        if not path.is_file():
            return
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                self._history = [item for item in loaded if isinstance(item, dict)]
        except (OSError, ValueError):
            self._history = []

    def _append_history(self, action: str, version: str, detail: str) -> None:
        entry = {"action": action, "version": version, "channel": self.channel, "detail": detail, "recorded_at": _iso()}
        self._history.append(entry)
        try:
            self._history_path().write_text(json.dumps(self._history[-200:], indent=2), encoding="utf-8")
        except OSError:
            pass

    def check_manifest(self, manifest: dict[str, Any], *, source: str = "local_manifest") -> dict[str, Any]:
        """Evaluate a release manifest from a trusted source without running anything."""
        if source.startswith("http://"):
            result = {
                "checked_at": _iso(),
                "trusted": False,
                "update_available": False,
                "reason": "unencrypted HTTP update sources are refused",
                "current_version": self.current_version,
            }
            self._last_check = result
            return result
        if self.trusted_sources and source not in self.trusted_sources:
            result = {
                "checked_at": _iso(),
                "trusted": False,
                "update_available": False,
                "reason": f"source '{source}' is not in the configured trusted_sources list",
                "current_version": self.current_version,
            }
            self._last_check = result
            return result
        if any(key in manifest for key in ("install_script", "post_install_shell", "remote_exec")):
            result = {
                "checked_at": _iso(),
                "trusted": False,
                "update_available": False,
                "reason": "manifest attempts to supply an executable script; remote update scripts are never executed",
                "current_version": self.current_version,
            }
            self._last_check = result
            return result

        releases_raw = manifest.get("releases") or []
        matching: list[ReleaseDescriptor] = []
        for item in releases_raw:
            if not isinstance(item, dict) or not item.get("version"):
                continue
            rel = ReleaseDescriptor(
                version=str(item["version"]),
                channel=str(item.get("channel") or CHANNEL_STABLE),
                sha256=str(item.get("sha256") or ""),
                release_notes=str(item.get("release_notes") or ""),
                min_python=str(item.get("min_python") or "3.11"),
                platforms=tuple(str(p).lower() for p in (item.get("platforms") or ("linux",))),
                artifact_name=str(item.get("artifact_name") or ""),
                signed=bool(item.get("signed", False)),
                signature_ref=str(item.get("signature_ref") or ""),
                origin=str(item.get("origin") or source),
                published_at=str(item.get("published_at") or ""),
            )
            if self.channel == CHANNEL_STABLE and rel.channel != CHANNEL_STABLE:
                continue
            if is_newer_version(rel.version, self.current_version):
                matching.append(rel)

        matching.sort(key=lambda r: parse_version(r.version), reverse=True)
        latest = matching[0] if matching else None
        compatibility = self.check_compatibility(latest) if latest else {"compatible": True, "issues": []}
        result = {
            "checked_at": _iso(),
            "trusted": True,
            "current_version": self.current_version,
            "channel": self.channel,
            "update_available": latest is not None,
            "latest": latest.to_dict() if latest else None,
            "compatibility": compatibility,
            "remote_script_execution": REMOTE_SCRIPT_EXECUTION,
        }
        self._last_check = result
        return result

    @staticmethod
    def check_compatibility(release: ReleaseDescriptor) -> dict[str, Any]:
        issues: list[str] = []
        host_os = platform.system().lower()
        if release.platforms and host_os not in release.platforms:
            issues.append(f"release targets {release.platforms}, host is '{host_os}'")
        req_parts = [int(p) for p in release.min_python.split(".")[:2] if p.isdigit()]
        if len(req_parts) == 2 and (sys.version_info.major, sys.version_info.minor) < (req_parts[0], req_parts[1]):
            issues.append(f"requires Python >= {release.min_python}")
        if release.origin == "ai_model":
            issues.append("AI-proposed builds cannot replace the stable application directly")
        return {"compatible": not issues, "issues": issues}

    @staticmethod
    def verify_artifact(artifact_path: Path, expected_sha256: str) -> dict[str, Any]:
        if not expected_sha256 or len(expected_sha256.strip()) != 64:
            return {"verified": False, "reason": "expected_sha256 must be a 64-character hex digest"}
        target = Path(artifact_path)
        if not target.is_file():
            return {"verified": False, "reason": "artifact file does not exist"}
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        matched = digest.lower() == expected_sha256.strip().lower()
        return {
            "verified": matched,
            "actual_sha256": digest,
            "expected_sha256": expected_sha256.strip().lower(),
            "reason": "SHA-256 digest matches" if matched else "SHA-256 digest mismatch — artifact rejected",
        }

    def check_migrations(self) -> dict[str, Any]:
        """Verify required core, cognition and platform tables exist without mutating data."""
        required_tables = {
            "tasks",
            "conversations",
            "messages",
            "autonomy_policy",
            "goals",
            "desktop_settings",
            "cognition_procedures",
            "cognition_calibration",
        }
        try:
            with sqlite3.connect(self.db.path) as conn:
                rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                present = {str(r[0]) for r in rows}
                integrity = conn.execute("PRAGMA quick_check").fetchone()
                integrity_ok = bool(integrity and integrity[0] == "ok")
        except sqlite3.Error as exc:
            return {"ok": False, "missing_tables": sorted(required_tables), "integrity_ok": False, "error": str(exc)}
        missing = sorted(required_tables - present)
        return {"ok": not missing and integrity_ok, "missing_tables": missing, "integrity_ok": integrity_ok}

    def create_backup(self, *, extra_settings: dict[str, Any] | None = None) -> BackupRecord:
        """Create an atomic SQLite + settings snapshot before applying an update."""
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        backup_id = f"bkp-{self.current_version}-{stamp}"
        folder = self.staging_dir / "backups" / backup_id
        folder.mkdir(parents=True, exist_ok=True)
        db_target = folder / "nova.sqlite3"
        with sqlite3.connect(self.db.path) as src, sqlite3.connect(db_target) as dst:
            src.backup(dst)
        policy = self.db.get_autonomy_policy()
        settings_payload = {
            "backed_up_at": _iso(),
            "version": self.current_version,
            "autonomy_policy": policy,
            "extra_settings": dict(extra_settings or {}),
        }
        settings_target = folder / "settings.json"
        settings_target.write_text(json.dumps(settings_payload, indent=2), encoding="utf-8")
        record = BackupRecord(
            backup_id=backup_id,
            created_at=_iso(),
            from_version=self.current_version,
            db_backup_path=str(db_target),
            settings_backup_path=str(settings_target),
            preserved_keys=tuple(sorted(["autonomy_policy", *(extra_settings or {}).keys()])),
        )
        self._append_history("backup_created", self.current_version, f"backup {backup_id}")
        return record

    def restore_backup(self, backup: BackupRecord) -> dict[str, Any]:
        """Restore database and settings from a verified backup after a failed update."""
        src_db = Path(backup.db_backup_path)
        src_settings = Path(backup.settings_backup_path)
        if not src_db.is_file() or not src_settings.is_file():
            return {"restored": False, "reason": "backup files are missing"}
        with sqlite3.connect(src_db) as src, sqlite3.connect(self.db.path) as dst:
            src.backup(dst)
        settings_data = json.loads(src_settings.read_text(encoding="utf-8"))
        self.current_version = str(settings_data.get("version") or backup.from_version)
        self._append_history("rolled_back", self.current_version, f"restored from {backup.backup_id}")
        return {
            "restored": True,
            "version": self.current_version,
            "backup_id": backup.backup_id,
            "settings": settings_data.get("extra_settings", {}),
        }

    def stage_and_apply(
        self,
        release: ReleaseDescriptor,
        *,
        artifact_path: Path,
        launch_probe: Callable[[], bool],
        operator_confirmed: bool = False,
        extra_settings: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Stage a release, back up user data, verify launch, and roll back if anything fails."""
        if release.origin == "ai_model":
            return {
                "applied": False,
                "rolled_back": False,
                "reason": "refused: an AI-proposed build cannot replace the stable application",
                "stable_version": self.current_version,
            }
        if not operator_confirmed:
            return {
                "applied": False,
                "rolled_back": False,
                "reason": "operator confirmation is required before applying an application update",
                "stable_version": self.current_version,
            }
        compatibility = self.check_compatibility(release)
        if not compatibility["compatible"]:
            return {
                "applied": False,
                "rolled_back": False,
                "reason": "incompatible release: " + "; ".join(compatibility["issues"]),
                "stable_version": self.current_version,
            }
        integrity = self.verify_artifact(artifact_path, release.sha256)
        if not integrity["verified"]:
            return {
                "applied": False,
                "rolled_back": False,
                "reason": integrity["reason"],
                "stable_version": self.current_version,
            }
        migration = self.check_migrations()
        if not migration["ok"]:
            return {
                "applied": False,
                "rolled_back": False,
                "reason": "pre-update database migration check failed",
                "migration": migration,
                "stable_version": self.current_version,
            }

        backup = self.create_backup(extra_settings=extra_settings)
        candidate_dir = self.staging_dir / "candidates" / release.version
        candidate_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(artifact_path, candidate_dir / Path(artifact_path).name)

        try:
            launched = bool(launch_probe())
        except Exception as exc:
            launched = False
            probe_error = f"{type(exc).__name__}: {exc}"
        else:
            probe_error = ""

        if not launched:
            restored = self.restore_backup(backup)
            return {
                "applied": False,
                "rolled_back": restored["restored"],
                "reason": f"candidate launch check failed ({probe_error or 'returned False'}); stable installation preserved",
                "stable_version": self.current_version,
                "backup": backup.to_dict(),
                "rollback_guidance": self.rollback_guidance(backup),
            }

        previous = self.current_version
        self.current_version = release.version
        self._append_history("updated", release.version, f"upgraded from {previous}")
        return {
            "applied": True,
            "rolled_back": False,
            "previous_version": previous,
            "current_version": self.current_version,
            "backup": backup.to_dict(),
            "rollback_guidance": self.rollback_guidance(backup),
        }

    @staticmethod
    def rollback_guidance(backup: BackupRecord) -> list[str]:
        return [
            f"1. Stop active NOVA workers before restoring backup '{backup.backup_id}'.",
            f"2. Restore SQLite state from '{backup.db_backup_path}' and settings from '{backup.settings_backup_path}'.",
            f"3. Reinstall the previous Debian package 'nova-x-desktop_{backup.from_version}_all.deb' via 'sudo dpkg -i'.",
        ]

    def status(self) -> dict[str, Any]:
        return {
            "current_version": self.current_version,
            "channel": self.channel,
            "update_available": bool(self._last_check and self._last_check.get("update_available")),
            "last_check": self._last_check,
            "history": list(self._history[-20:]),
            "remote_script_execution": REMOTE_SCRIPT_EXECUTION,
        }


@dataclass(frozen=True)
class QueuedOfflineTask:
    queue_id: str
    objective: str
    queued_at: str
    required_tool: str
    assumptions: tuple[str, ...]
    permission_snapshot: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "queue_id": self.queue_id,
            "objective": self.objective,
            "queued_at": self.queued_at,
            "required_tool": self.required_tool,
            "assumptions": list(self.assumptions),
            "permission_snapshot": self.permission_snapshot,
        }


@dataclass
class OfflineCoordinator:
    """§106 Offline and degraded-operation controller."""

    resources: ResourceManager = field(default_factory=ResourceManager)
    mode: str = MODE_ONLINE
    degraded_reason: str = ""
    local_runtime_binary: str = "ollama"
    min_ram_mb_for_local_model: int = 3_072
    _queue: list[QueuedOfflineTask] = field(default_factory=list, init=False)
    _counter: int = field(default=0, init=False)

    def set_mode(self, mode: str, *, reason: str = "") -> dict[str, Any]:
        if mode not in OPERATION_MODES:
            raise ValueError(f"Unknown operation mode: {mode}")
        self.mode = mode
        self.degraded_reason = reason
        return self.status()

    def assess_local_inference(self, *, requested_model_mb: int = 2_048) -> dict[str, Any]:
        """Check whether an installed local runtime (e.g. Ollama) can run safely on this PC."""
        binary = shutil.which(self.local_runtime_binary)
        budget = self.resources.assess()
        sample = budget.sample
        avail_mb = sample.memory_available_mb if sample else 0
        if not binary:
            return {
                "usable": False,
                "runtime": self.local_runtime_binary,
                "reason": f"'{self.local_runtime_binary}' is not installed; local inference is optional and not required",
                "auto_download_permitted": AUTO_MODEL_DOWNLOAD_PERMITTED,
            }
        needed_mb = max(self.min_ram_mb_for_local_model, int(requested_model_mb) + 1_024)
        if avail_mb and avail_mb < needed_mb:
            return {
                "usable": False,
                "runtime": self.local_runtime_binary,
                "available_ram_mb": avail_mb,
                "required_ram_mb": needed_mb,
                "reason": f"available RAM ({avail_mb} MB) is below safe threshold ({needed_mb} MB) for a {requested_model_mb} MB model",
                "auto_download_permitted": AUTO_MODEL_DOWNLOAD_PERMITTED,
            }
        return {
            "usable": True,
            "runtime": self.local_runtime_binary,
            "binary_path": binary,
            "available_ram_mb": avail_mb,
            "auto_download_permitted": AUTO_MODEL_DOWNLOAD_PERMITTED,
            "note": "Models must already be present locally; NOVA never downloads large weights automatically.",
        }

    def enqueue_for_online(
        self,
        *,
        objective: str,
        required_tool: str = "",
        assumptions: tuple[str, ...] = (),
        permission_snapshot: dict[str, Any] | None = None,
    ) -> QueuedOfflineTask:
        self._counter += 1
        item = QueuedOfflineTask(
            queue_id=f"offq-{self._counter:04d}",
            objective=objective,
            queued_at=_iso(),
            required_tool=required_tool,
            assumptions=tuple(assumptions),
            permission_snapshot=dict(permission_snapshot or {}),
        )
        self._queue.append(item)
        return item

    def prepare_resume(
        self,
        queue_id: str,
        *,
        permission_check: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
        assumption_validator: Callable[[str], bool] | None = None,
    ) -> dict[str, Any]:
        """Revalidate permissions and assumptions before resuming queued offline work (§106)."""
        target = next((item for item in self._queue if item.queue_id == queue_id), None)
        if target is None:
            return {"resumable": False, "reason": f"queued item '{queue_id}' not found"}
        if self.mode != MODE_ONLINE:
            return {"resumable": False, "reason": f"system is still in '{self.mode}' mode"}

        failed_assumptions = [
            assumption
            for assumption in target.assumptions
            if assumption_validator is not None and not bool(assumption_validator(assumption))
        ]
        if failed_assumptions:
            return {
                "resumable": False,
                "queue_id": queue_id,
                "reason": "queued task assumptions no longer hold",
                "failed_assumptions": failed_assumptions,
            }
        if target.required_tool and permission_check is not None:
            decision = permission_check(target.required_tool, {})
            if decision.get("action") != "allow":
                return {
                    "resumable": False,
                    "queue_id": queue_id,
                    "reason": f"permission revalidation denied '{target.required_tool}': {decision.get('reason', '')}",
                }
        self._queue = [item for item in self._queue if item.queue_id != queue_id]
        return {"resumable": True, "task": target.to_dict()}

    def guard_online_operation(self, operation: str) -> dict[str, Any]:
        """Refuse to fabricate model output or fresh web research when offline (§106)."""
        if self.mode == MODE_ONLINE:
            return {"allowed": True, "mode": self.mode, "operation": operation}
        return {
            "allowed": False,
            "mode": self.mode,
            "operation": operation,
            "fabricated": False,
            "reason": (
                f"'{operation}' is unavailable while NOVA is in '{self.mode}' mode"
                + (f" ({self.degraded_reason})" if self.degraded_reason else "")
                + ". NOVA will not fabricate a model response or claim fresh internet research occurred."
            ),
            "offline_alternatives": list(OFFLINE_CAPABILITIES),
        }

    def status(self) -> dict[str, Any]:
        degraded = list(ONLINE_ONLY_CAPABILITIES) if self.mode != MODE_ONLINE else []
        return {
            "mode": self.mode,
            "degraded": self.mode != MODE_ONLINE,
            "reason": self.degraded_reason,
            "available_offline": list(OFFLINE_CAPABILITIES),
            "degraded_capabilities": degraded,
            "queued_tasks": [item.to_dict() for item in self._queue],
            "auto_model_download_permitted": AUTO_MODEL_DOWNLOAD_PERMITTED,
            "fabricates_responses_when_offline": False,
        }


__all__ = [
    "AUTO_MODEL_DOWNLOAD_PERMITTED",
    "CHANNEL_CANDIDATE",
    "CHANNEL_DEVELOPMENT",
    "CHANNEL_STABLE",
    "MODE_OFFLINE",
    "MODE_ONLINE",
    "MODE_PROVIDER_UNAVAILABLE",
    "OFFLINE_CAPABILITIES",
    "ONLINE_ONLY_CAPABILITIES",
    "OPERATION_MODES",
    "RELEASE_CHANNELS",
    "REMOTE_SCRIPT_EXECUTION",
    "BackupRecord",
    "OfflineCoordinator",
    "QueuedOfflineTask",
    "ReleaseDescriptor",
    "UpdateManager",
    "is_newer_version",
    "parse_version",
]
