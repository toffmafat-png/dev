"""§153 Autostart & Background Service, §154 Power-Off/Crash Recovery & Durable
Task State, §161 Startup/Recovery Policy, §162 Continuous Autonomy with Human
Authority, and §163 Resilience Requirements.
"""
from __future__ import annotations

import getpass
import hashlib
import json
import os
import shutil
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nova.db import Database

USES_UNDOCUMENTED_DAEMONIZATION = False

DEFAULT_STARTUP_TOGGLES: dict[str, bool] = {
    "start_desktop_at_login": False,
    "start_user_worker_at_login": False,
    "start_system_service_at_boot": False,
    "auto_restore_interrupted_tasks": False,
    "auto_resume_scheduled_workflows": False,
    "auto_restart_monitoring": True,
    "restore_dashboard_pages": True,
    "reopen_last_project": False,
    "resume_screen_recording": False,
}

# §161: Every startup/recovery toggle discloses running account, purpose, and permissions BEFORE enabling.
STARTUP_TOGGLE_DISCLOSURES: dict[str, dict[str, str]] = {
    "start_desktop_at_login": {
        "runs_as_account": "logged-in desktop user (`~/.config/autostart/nova-x-desktop.desktop`)",
        "purpose": "Launch the NOVA X Control Center window when a graphical X11/Wayland session starts.",
        "permissions_used": "Unprivileged user session + display socket (`DISPLAY`/`WAYLAND_DISPLAY`).",
    },
    "start_user_worker_at_login": {
        "runs_as_account": "logged-in user (`systemd --user` unit `nova-x-worker.service`)",
        "purpose": "Run the bounded background queue, recovery journal monitor, and local API listener.",
        "permissions_used": "Unprivileged user account; no root privileges.",
    },
    "start_system_service_at_boot": {
        "runs_as_account": "dedicated unprivileged `novax` service user (`/etc/systemd/system/nova-x-node.service`)",
        "purpose": "Start authorized node/server monitoring at boot before graphical login.",
        "permissions_used": "Requires explicit administrator installation via Polkit/systemd; disabled by default.",
    },
    "auto_restore_interrupted_tasks": {
        "runs_as_account": "logged-in user worker",
        "purpose": "Resume interrupted tasks whose current step is verified idempotent (`resume_policy='auto_safe'`).",
        "permissions_used": "Task workspace read/write within previously granted project scope.",
    },
    "auto_resume_scheduled_workflows": {
        "runs_as_account": "logged-in user worker",
        "purpose": "Re-enable user-created cron/interval workflows after clean startup.",
        "permissions_used": "Scoped workflow tools only; paused automatically in Safe Recovery Mode.",
    },
    "auto_restart_monitoring": {
        "runs_as_account": "logged-in user worker",
        "purpose": "Resume low-overhead system, storage, and network health sampling.",
        "permissions_used": "Read-only `/proc` and `/sys` telemetry.",
    },
    "restore_dashboard_pages": {
        "runs_as_account": "logged-in desktop user",
        "purpose": "Reopen the last viewed Control Center navigation tab on UI launch.",
        "permissions_used": "Local UI state file only.",
    },
    "reopen_last_project": {
        "runs_as_account": "logged-in desktop user",
        "purpose": "Restore active project workspace context into the Studio/Coding view.",
        "permissions_used": "Read access to the user's last opened project directory.",
    },
    "resume_screen_recording": {
        "runs_as_account": "logged-in desktop user",
        "purpose": "Prompt or start a new recording segment after restart (never silently captures without indicator).",
        "permissions_used": "Graphical session portal/display permission + visible recording indicator.",
    },
}

REQUIRED_JOURNAL_FIELDS: tuple[str, ...] = (
    "task_id",
    "goal",
    "plan",
    "current_step",
    "completed_steps",
    "pending_steps",
    "tool_calls_in_progress",
    "produced_artifacts",
    "modified_files",
    "temporary_files",
    "remote_operations_in_progress",
    "approval_states",
    "retry_counts",
    "last_checkpoint_time",
    "recovery_instructions",
    "idempotency_keys",
    "resume_policy",
)


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(65536):
            h.update(chunk)
    return h.hexdigest()


class StartupRecoveryPolicyManager:
    """§153, §161, §162 Startup, Background Service, Config Backup, and Autonomy Gate."""

    ROUTINE_AUTONOMOUS_ACTIONS: frozenset[str] = frozenset(
        {
            "inspect_hardware",
            "read_logs",
            "local_search",
            "local_file_write",
            "run_tests",
            "checkpoint_save",
            "documentation_lookup",
            "verify_artifact",
        }
    )

    def __init__(self, *, db: Database, state_dir: Path) -> None:
        self.db = db
        self.state_dir = state_dir
        self.config_dir = state_dir / "config"
        self.backup_dir = state_dir / "config_backups"
        self.log_dir = state_dir / "logs"
        self.autostart_dir = state_dir / "autostart"
        self.systemd_user_dir = state_dir / "systemd_user"
        for d in (self.config_dir, self.backup_dir, self.log_dir, self.autostart_dir, self.systemd_user_dir):
            d.mkdir(parents=True, exist_ok=True)
        self._emergency_stop = False

    def _raw_policy_bundle(self) -> dict[str, Any]:
        return self.db.get_startup_recovery_policy(defaults=DEFAULT_STARTUP_TOGGLES)

    def get_policy_with_disclosures(self) -> dict[str, Any]:
        bundle = self._raw_policy_bundle()
        toggles = {**DEFAULT_STARTUP_TOGGLES, **dict(bundle.get("policy") or {})}
        return {
            "current_user": getpass.getuser(),
            "uses_undocumented_daemonization": USES_UNDOCUMENTED_DAEMONIZATION,
            "emergency_stop_active": self._emergency_stop,
            "safe_recovery_mode": bool(bundle.get("safe_recovery_mode")),
            "last_unclean_shutdown_reason": str(bundle.get("last_unclean_shutdown_reason") or ""),
            "policy": toggles,
            "disclosures": STARTUP_TOGGLE_DISCLOSURES,
        }

    def update_policy(self, updates: dict[str, Any]) -> dict[str, Any]:
        bundle = self._raw_policy_bundle()
        merged = {**DEFAULT_STARTUP_TOGGLES, **dict(bundle.get("policy") or {})}
        for k in DEFAULT_STARTUP_TOGGLES:
            if k in updates:
                merged[k] = bool(updates[k])
        safe_mode = updates.get("safe_recovery_mode") if "safe_recovery_mode" in updates else None
        self.db.update_startup_recovery_policy(merged, safe_recovery_mode=safe_mode)
        self._sync_autostart_files(merged)
        return self.get_policy_with_disclosures()

    def enter_safe_recovery_mode(self, reason: str) -> dict[str, Any]:
        bundle = self._raw_policy_bundle()
        updated = self.db.update_startup_recovery_policy(
            dict(bundle.get("policy") or DEFAULT_STARTUP_TOGGLES),
            safe_recovery_mode=True,
            last_unclean_shutdown_reason=reason[:300],
        )
        return updated

    def exit_safe_recovery_mode(self) -> dict[str, Any]:
        bundle = self._raw_policy_bundle()
        return self.db.update_startup_recovery_policy(
            dict(bundle.get("policy") or DEFAULT_STARTUP_TOGGLES),
            safe_recovery_mode=False,
            last_unclean_shutdown_reason="",
        )

    def trigger_emergency_stop(self, reason: str = "Operator triggered emergency stop") -> dict[str, Any]:
        self._emergency_stop = True
        pol = self.enter_safe_recovery_mode(reason)
        return {"emergency_stop_active": True, "safe_recovery_mode": pol["safe_recovery_mode"], "reason": reason}

    def clear_emergency_stop(self) -> dict[str, Any]:
        self._emergency_stop = False
        return {"emergency_stop_active": False}

    def evaluate_autonomy_gate(
        self,
        action_kind: str,
        *,
        missing_credentials: bool = False,
        crosses_security_boundary: bool = False,
        destructive_or_irreversible: bool = False,
        low_resources: bool = False,
    ) -> dict[str, Any]:
        """§162: Routine work executes autonomously; consult user ONLY on genuine authority/resource boundaries."""
        if self._emergency_stop:
            return {"proceed_autonomously": False, "consult_user": True, "reason": "emergency_stop_active"}
        bundle = self._raw_policy_bundle()
        if bundle.get("safe_recovery_mode") and action_kind not in {"inspect_hardware", "read_logs", "verify_artifact"}:
            return {"proceed_autonomously": False, "consult_user": True, "reason": "safe_recovery_mode_paused_automations"}
        if missing_credentials:
            return {"proceed_autonomously": False, "consult_user": True, "reason": "missing_credentials"}
        if crosses_security_boundary:
            return {"proceed_autonomously": False, "consult_user": True, "reason": "security_boundary_approval_required"}
        if destructive_or_irreversible:
            return {"proceed_autonomously": False, "consult_user": True, "reason": "high_impact_irreversible_risk"}
        if low_resources:
            return {"proceed_autonomously": False, "consult_user": True, "reason": "system_resources_critically_low"}
        return {
            "proceed_autonomously": True,
            "consult_user": False,
            "reason": "routine_authorized_execution" if action_kind in self.ROUTINE_AUTONOMOUS_ACTIONS else "within_granted_scope",
        }

    def _sync_autostart_files(self, pol: dict[str, Any]) -> None:
        desktop_file = self.autostart_dir / "nova-x-desktop.desktop"
        if pol.get("start_desktop_at_login"):
            desktop_file.write_text(
                "[Desktop Entry]\n"
                "Type=Application\n"
                "Name=NOVA X Desktop Control Center\n"
                "Comment=Unified AI Operating Desktop (User Session)\n"
                "Exec=nova-x-desktop\n"
                "Terminal=false\n"
                "X-GNOME-Autostart-enabled=true\n",
                encoding="utf-8",
            )
        elif desktop_file.exists():
            desktop_file.unlink()

        unit_file = self.systemd_user_dir / "nova-x-worker.service"
        if pol.get("start_user_worker_at_login"):
            unit_file.write_text(self.generate_systemd_user_unit(), encoding="utf-8")
        elif unit_file.exists():
            unit_file.unlink()

    @staticmethod
    def generate_systemd_user_unit() -> str:
        return (
            "[Unit]\n"
            "Description=NOVA X Unprivileged Background Worker & Recovery Supervisor\n"
            "After=default.target network-online.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            "ExecStart=/usr/bin/env nova-x-service\n"
            "Restart=on-failure\n"
            "RestartSec=5\n"
            "Nice=5\n"
            "MemoryMax=2G\n"
            "CPUQuota=150%\n"
            "NoNewPrivileges=yes\n\n"
            "[Install]\n"
            "WantedBy=default.target\n"
        )

    def save_config_with_backup(self, name: str, payload: dict[str, Any]) -> dict[str, Any]:
        safe_name = "".join(c for c in name if c.isalnum() or c in {"-", "_"}) or "settings"
        target = self.config_dir / f"{safe_name}.json"
        if target.exists():
            ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ%f")
            shutil.copy2(target, self.backup_dir / f"{safe_name}.{ts}.bak.json")
        tmp = self.config_dir / f".{safe_name}.json.tmp"
        serialized = json.dumps(payload, indent=2, sort_keys=True)
        tmp.write_text(serialized, encoding="utf-8")
        os.replace(tmp, target)
        return {"config_path": str(target), "bytes": len(serialized)}

    def load_config_resilient(self, name: str, default: dict[str, Any] | None = None) -> dict[str, Any]:
        safe_name = "".join(c for c in name if c.isalnum() or c in {"-", "_"}) or "settings"
        target = self.config_dir / f"{safe_name}.json"
        if target.exists():
            try:
                data = json.loads(target.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return {"recovered_from_backup": False, "data": data}
            except ValueError:
                pass
        for bak in sorted(self.backup_dir.glob(f"{safe_name}.*.bak.json"), reverse=True):
            try:
                data = json.loads(bak.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    shutil.copy2(bak, target)
                    return {"recovered_from_backup": True, "backup_used": str(bak), "data": data}
            except ValueError:
                continue
        return {"recovered_from_backup": False, "data": dict(default or {})}

    def rotate_logs(self, log_name: str = "worker.log", *, max_bytes: int = 2_000_000, backups: int = 3) -> dict[str, Any]:
        log_path = self.log_dir / log_name
        if not log_path.exists() or log_path.stat().st_size <= max_bytes:
            return {"rotated": False, "path": str(log_path), "size": log_path.stat().st_size if log_path.exists() else 0}
        for idx in range(backups - 1, 0, -1):
            src = self.log_dir / f"{log_name}.{idx}"
            dst = self.log_dir / f"{log_name}.{idx + 1}"
            if src.exists():
                os.replace(src, dst)
        os.replace(log_path, self.log_dir / f"{log_name}.1")
        log_path.write_text("", encoding="utf-8")
        return {"rotated": True, "path": str(log_path), "archived_to": str(self.log_dir / f"{log_name}.1")}


class DurableTaskJournal:
    """§154 & §163 Durable WAL-Backed Task Checkpointing and Idempotent Restart Recovery."""

    def __init__(self, *, db: Database, policy_manager: StartupRecoveryPolicyManager) -> None:
        self.db = db
        self.policy_manager = policy_manager

    @staticmethod
    def _normalize_journal_view(raw: dict[str, Any]) -> dict[str, Any]:
        cp = dict(raw.get("last_checkpoint") or {})
        return {
            "task_id": raw["task_id"],
            "goal": raw.get("objective") or cp.get("goal") or "",
            "plan": list(raw.get("execution_plan") or []),
            "current_step": str(cp.get("current_step_name") or raw.get("current_step") or ""),
            "completed_steps": list(raw.get("completed_steps") or []),
            "pending_steps": list(raw.get("pending_steps") or []),
            "tool_calls_in_progress": list(cp.get("tool_calls_in_progress") or []),
            "produced_artifacts": list(raw.get("expected_outputs") or []),
            "modified_files": list(cp.get("modified_files") or []),
            "temporary_files": list(cp.get("temporary_files") or []),
            "remote_operations_in_progress": list(cp.get("remote_operations_in_progress") or []),
            "approval_states": dict(raw.get("permissions") or {}),
            "retry_counts": dict(cp.get("retry_counts") or {"total": raw.get("retry_count", 0)}),
            "last_checkpoint_time": str(cp.get("last_checkpoint_time") or raw.get("updated_at") or _iso()),
            "recovery_instructions": str(cp.get("recovery_instructions") or ""),
            "idempotency_keys": list(cp.get("idempotency_keys") or []),
            "resume_policy": str(cp.get("resume_policy") or "confirm"),
            "status": str(raw.get("verification_status") or "running"),
        }

    def checkpoint_task(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Atomically persist all 17 §154 durable task state fields into `task_recovery_journal`."""
        status = str(payload.get("status") or "running")
        now = _iso()
        cp_meta = {
            "goal": str(payload.get("goal") or payload.get("objective") or ""),
            "current_step_name": str(payload.get("current_step") or ""),
            "tool_calls_in_progress": list(payload.get("tool_calls_in_progress") or []),
            "modified_files": list(payload.get("modified_files") or []),
            "temporary_files": list(payload.get("temporary_files") or []),
            "remote_operations_in_progress": list(payload.get("remote_operations_in_progress") or []),
            "retry_counts": dict(payload.get("retry_counts") or {}),
            "last_checkpoint_time": str(payload.get("last_checkpoint_time") or now),
            "recovery_instructions": str(payload.get("recovery_instructions") or ""),
            "idempotency_keys": list(payload.get("idempotency_keys") or []),
            "resume_policy": str(payload.get("resume_policy") or "confirm"),
        }
        raw = self.db.upsert_task_journal(
            {
                "task_id": str(payload["task_id"]),
                "objective": cp_meta["goal"],
                "permissions": dict(payload.get("approval_states") or {}),
                "execution_plan": list(payload.get("plan") or []),
                "current_step": 0,
                "completed_steps": list(payload.get("completed_steps") or []),
                "pending_steps": list(payload.get("pending_steps") or []),
                "expected_outputs": list(payload.get("produced_artifacts") or []),
                "verification_status": status,
                "active_before_shutdown": status in {"running", "in_progress", "interrupted"},
                "last_checkpoint": cp_meta,
            }
        )
        view = self._normalize_journal_view(raw)
        for field_name in REQUIRED_JOURNAL_FIELDS:
            assert field_name in view, f"Missing required §154 journal field: {field_name}"
        return view

    def get_checkpoint(self, task_id: str) -> dict[str, Any] | None:
        raw = self.db.get_task_journal(task_id)
        return self._normalize_journal_view(raw) if raw else None

    def execute_idempotent_step(
        self,
        *,
        task_id: str,
        step_id: str,
        idempotency_key: str,
        operation_kind: str,
        target_path: Path | None,
        action_fn: Callable[[], dict[str, Any]],
    ) -> dict[str, Any]:
        """Execute a side-effecting step once; skip re-execution if already verified complete."""
        existing = self.db.get_operation_idempotency(idempotency_key)
        if existing and existing["state"] == "completed":
            exp_sha = str(existing["expected_effect"].get("expected_sha256") or "")
            if target_path is None or (
                target_path.exists() and (not exp_sha or _file_sha256(target_path) == exp_sha)
            ):
                return {
                    "executed": False,
                    "skipped_duplicate": True,
                    "idempotency_key": idempotency_key,
                    "previous_result": existing["observed_result"],
                }

        self.db.upsert_operation_idempotency(
            {
                "idempotency_key": idempotency_key,
                "task_id": task_id,
                "step_index": 0,
                "operation_kind": operation_kind,
                "repeatable": False,
                "state": "in_progress",
                "expected_effect": {"step_id": step_id, "verify_target": str(target_path) if target_path else ""},
                "observed_result": {},
            }
        )

        result = action_fn()
        sha = _file_sha256(target_path) if (target_path and target_path.exists() and target_path.is_file()) else ""
        self.db.upsert_operation_idempotency(
            {
                "idempotency_key": idempotency_key,
                "task_id": task_id,
                "step_index": 0,
                "operation_kind": operation_kind,
                "repeatable": False,
                "state": "completed",
                "expected_effect": {
                    "step_id": step_id,
                    "verify_target": str(target_path) if target_path else "",
                    "expected_sha256": sha,
                },
                "observed_result": result,
                "completed_at": _iso(),
            }
        )
        return {"executed": True, "skipped_duplicate": False, "idempotency_key": idempotency_key, "result": result}

    def recover_after_restart(
        self,
        *,
        remote_state_inspector: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """§154 10-Step Restart Recovery:
        Inspects actual disk/remote state before repeating ANY side-effecting step;
        never assumes an interrupted step failed merely because its process vanished.
        """
        db_ok = self.db.quick_check()
        pol_view = self.policy_manager.get_policy_with_disclosures()
        safe_mode = bool(pol_view["safe_recovery_mode"])
        auto_restore = bool(pol_view["policy"].get("auto_restore_interrupted_tasks")) and not safe_mode

        raw_entries = self.db.list_task_journals(active_only=True)
        decisions: list[dict[str, Any]] = []
        cleaned_temp_files: list[str] = []

        for raw in raw_entries:
            entry = self._normalize_journal_view(raw)
            task_id = entry["task_id"]
            completed = list(entry["completed_steps"])
            pending = list(entry["pending_steps"])
            in_flight_tools = list(entry["tool_calls_in_progress"])
            remote_ops = list(entry["remote_operations_in_progress"])
            cur_step = entry["current_step"]

            remaining_temps: list[str] = []
            for tpath_str in entry["temporary_files"]:
                tp = Path(tpath_str)
                if tp.exists() and tp.is_file() and (tp.name.endswith(".tmp") or tp.name.endswith(".part")):
                    try:
                        tp.unlink()
                        cleaned_temp_files.append(tpath_str)
                        continue
                    except OSError:
                        pass
                if tp.exists():
                    remaining_temps.append(tpath_str)

            verified_side_effects: list[str] = []
            ambiguous_non_idempotent = False
            for ikey in entry["idempotency_keys"]:
                rec = self.db.get_operation_idempotency(ikey)
                if not rec:
                    continue
                eff = dict(rec.get("expected_effect") or {})
                step_id = str(eff.get("step_id") or "")
                vtarget_str = str(eff.get("verify_target") or "")
                vtarget = Path(vtarget_str) if vtarget_str else None
                if rec["state"] in {"started", "in_progress"} and vtarget is not None and vtarget.exists() and vtarget.stat().st_size > 0:
                    sha = _file_sha256(vtarget) if vtarget.is_file() else ""
                    self.db.upsert_operation_idempotency(
                        {
                            "idempotency_key": ikey,
                            "task_id": task_id,
                            "operation_kind": rec["operation_kind"],
                            "state": "completed",
                            "expected_effect": {**eff, "expected_sha256": sha},
                            "observed_result": {"recovered_from_disk_verification": True, "sha256": sha},
                            "completed_at": _iso(),
                        }
                    )
                    verified_side_effects.append(step_id)
                    if step_id and step_id not in completed:
                        completed.append(step_id)
                    if step_id in pending:
                        pending.remove(step_id)
                elif rec["state"] == "completed":
                    if step_id and step_id not in completed:
                        completed.append(step_id)
                    if step_id in pending:
                        pending.remove(step_id)

            unresolved_remote: list[dict[str, Any]] = []
            for rop in remote_ops:
                if remote_state_inspector is not None:
                    rcheck = remote_state_inspector(rop)
                    if rcheck.get("completed"):
                        step_name = str(rop.get("step_id") or "")
                        if step_name and step_name not in completed:
                            completed.append(step_name)
                        if step_name in pending:
                            pending.remove(step_name)
                        verified_side_effects.append(step_name or "remote_op")
                        continue
                ambiguous_non_idempotent = True
                unresolved_remote.append(rop)

            if in_flight_tools and not verified_side_effects and entry["resume_policy"] != "auto_safe":
                ambiguous_non_idempotent = True

            if not pending and not unresolved_remote:
                new_status = "completed_recovered"
                classification = "completed_before_crash"
                next_step = ""
            elif safe_mode:
                new_status = "paused_safe_recovery"
                classification = "paused_safe_recovery_mode"
                next_step = pending[0] if pending else cur_step
            elif ambiguous_non_idempotent or entry["resume_policy"] == "confirm" or not auto_restore:
                new_status = "awaiting_confirmation"
                classification = "awaiting_user_confirmation"
                next_step = pending[0] if pending else cur_step
            else:
                new_status = "resumed"
                classification = "safely_resumed"
                next_step = pending[0] if pending else cur_step

            updated = self.checkpoint_task(
                {
                    **entry,
                    "current_step": next_step,
                    "completed_steps": completed,
                    "pending_steps": pending,
                    "tool_calls_in_progress": [],
                    "temporary_files": remaining_temps,
                    "remote_operations_in_progress": unresolved_remote,
                    "status": new_status,
                }
            )
            decisions.append(
                {
                    "task_id": task_id,
                    "goal": entry["goal"],
                    "classification": classification,
                    "status": updated["status"],
                    "verified_completed_steps_without_repeat": verified_side_effects,
                    "remaining_pending_steps": pending,
                    "cleaned_temp_files": cleaned_temp_files,
                }
            )

        return {
            "recovered_at": _iso(),
            "sqlite_integrity_ok": db_ok,
            "safe_recovery_mode": safe_mode,
            "auto_restore_enabled": auto_restore,
            "inspected_count": len(raw_entries),
            "cleaned_temp_files": cleaned_temp_files,
            "decisions": decisions,
        }
