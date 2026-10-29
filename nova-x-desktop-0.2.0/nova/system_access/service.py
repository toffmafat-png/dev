"""Unified §149–§164 System Access, Hardware Intelligence, Resilience, Recording,
Observability, Troubleshooting, and Remote Infrastructure Facade.

Bound directly onto `PlatformService` so every NOVA X surface (Desktop UI, CLI,
FastAPI, UnifiedOperatingKernel, and ToolRegistry) shares a single database,
policy boundary, secret store, and audit log.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from nova.db import Database
from nova.desktop.secrets import SecretStore
from nova.observability import Redactor
from nova.resources import ResourceManager
from nova.system_access.hardware import (
    DeviceOperationsController,
    DriverIntelligenceEngine,
    HardwareInventoryEngine,
)
from nova.system_access.observability_net import (
    InfrastructureKnowledgeEngine,
    PersistentTroubleshooter,
    SystemNetworkMonitor,
)
from nova.system_access.privilege import PrivilegedHelperClient, PrivilegedSystemHelper
from nova.system_access.recording import ScreenRecordingStudio
from nova.system_access.remote import (
    MultiDeviceNodeCoordinator,
    ProtectedCredentialVault,
    ServerRegistryAndAdmin,
)
from nova.system_access.resilience import DurableTaskJournal, StartupRecoveryPolicyManager


class SystemAccessService:
    """Cohesive §149–§164 subsystem wired into `PlatformService`."""

    def __init__(
        self,
        *,
        db: Database,
        secret_store: SecretStore | None = None,
        redactor: Redactor,
        resource_manager: ResourceManager,
        state_dir: Path,
        workspace_path: Path,
        worker_status_fn: Any = None,
    ) -> None:
        self.db = db
        self.secret_store = secret_store
        self.redactor = redactor
        self.state_dir = state_dir
        self.workspace_path = workspace_path
        self.vault = ProtectedCredentialVault(
            state_dir / "vault",
            redactor=redactor,
            secret_store=secret_store,
        )

        self.privileged_helper = PrivilegedSystemHelper(db=db, redactor=redactor)
        self.privileged_client = PrivilegedHelperClient(self.privileged_helper)

        self.hardware = HardwareInventoryEngine(db=db)
        self.drivers = DriverIntelligenceEngine(
            db=db,
            inventory=self.hardware,
            privileged_client=self.privileged_client,
        )
        self.device_ops = DeviceOperationsController(
            inventory=self.hardware,
            privileged_client=self.privileged_client,
        )

        self.startup_policy = StartupRecoveryPolicyManager(
            db=db,
            state_dir=state_dir / "resilience",
        )
        self.task_journal = DurableTaskJournal(
            db=db,
            policy_manager=self.startup_policy,
        )

        self.recording_studio = ScreenRecordingStudio(
            db=db,
            media_dir=state_dir / "media_studio",
        )

        self.servers = ServerRegistryAndAdmin(
            db=db,
            vault=self.vault,
            redactor=redactor,
            state_dir=state_dir,
        )
        self.nodes = MultiDeviceNodeCoordinator(
            db=db,
            vault=self.vault,
        )

        self.infra_knowledge = InfrastructureKnowledgeEngine(
            db=db,
            redactor=redactor,
        )
        self.troubleshooter = PersistentTroubleshooter(
            infra_knowledge=self.infra_knowledge,
            redactor=redactor,
        )
        self.monitor = SystemNetworkMonitor(
            db=db,
            resource_manager=resource_manager,
            workspace_path=workspace_path,
            worker_status_fn=worker_status_fn,
            recording_status_fn=self.recording_studio.get_indicator_state,
            unreachable_servers_fn=lambda: [
                s["alias"] for s in self.db.list_registered_servers() if s["connection_health"] in {"unreachable", "rejected_host_key_mismatch"}
            ],
        )

        # Perform non-destructive startup recovery sweep when schema is already initialized.
        try:
            self.last_startup_recovery = self.run_startup_recovery()
        except sqlite3.OperationalError:
            self.last_startup_recovery = {"tasks": {"inspected_count": 0}, "recordings": {"recovered_count": 0}}

    def run_startup_recovery(self) -> dict[str, Any]:
        tasks_rec = self.task_journal.recover_after_restart()
        recs_rec = self.recording_studio.recover_interrupted_recordings()
        return {
            "tasks": tasks_rec,
            "recordings": recs_rec,
        }

    def health_summary(self) -> dict[str, Any]:
        pol = self.db.get_startup_recovery_policy()
        ind = self.recording_studio.get_indicator_state()
        return {
            "sqlite_wal_ok": self.db.quick_check(),
            "safe_recovery_mode": bool(pol.get("safe_recovery_mode")),
            "emergency_stop_active": self.startup_policy._emergency_stop,
            "registered_servers": len(self.db.list_registered_servers()),
            "remote_nodes": len(self.db.list_remote_nodes()),
            "recording_active": bool(ind.get("recording_active")),
            "recording_badge": str(ind.get("badge_text") or ""),
            "infrastructure_records": len(self.db.list_infrastructure_knowledge()),
            "privileged_helper_operations": len(self.privileged_helper.capabilities()["defined_operations"]),
        }
