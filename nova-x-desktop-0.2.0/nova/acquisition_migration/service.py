"""§221–§235 Unified Autonomous Software Acquisition, Environment Management & Universal Migration Service."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from nova.acquisition_migration.discovery_and_provenance import (
    ACQUISITION_22_CATEGORIES,
    IntelligentSoftwareDiscoveryEngine,
    SoftwareProvenanceVerifier,
    UniversalPackageManagerDiscovery,
)
from nova.acquisition_migration.installer_lifecycle_env import (
    AutomaticDependencyResolver,
    AutonomousEnvironmentBuilder,
    AutonomousInstallationController,
    SoftwareLifecycleManager,
)
from nova.acquisition_migration.migration_and_backup import (
    BACKUP_11_KINDS,
    MIGRATION_6_SECTIONS,
    DevMigrationManager,
    OneClickBackupAndRestoreEngine,
)
from nova.capabilities import CapabilityRegistry
from nova.db import Database
from nova.kali_intel.service import KaliIntelligenceService
from nova.tools.registry import ToolRegistry


class AutonomousAcquisitionAndMigrationService:
    """§221–§235 Self-Provisioning Software Acquisition, Dependency/Environment Builder & Portable Migration Core."""

    def __init__(
        self,
        *,
        db: Database,
        workspace_dir: Path,
        kali_intel: KaliIntelligenceService,
        capabilities: CapabilityRegistry | None = None,
        tool_registry: ToolRegistry | None = None,
    ):
        self.db = db
        self.workspace_dir = workspace_dir
        self.kali_intel = kali_intel

        # §221, §222, §223 & §225
        self.pkg_managers = UniversalPackageManagerDiscovery()
        self.provenance = SoftwareProvenanceVerifier(db=db, workspace_dir=workspace_dir)
        self.discovery = IntelligentSoftwareDiscoveryEngine(
            db=db,
            workspace_dir=workspace_dir,
            system_model=kali_intel.system_model,
            pkg_managers=self.pkg_managers,
            provenance=self.provenance,
        )

        # §224, §226, §227 & §228
        self.installer = AutonomousInstallationController(
            db=db,
            workspace_dir=workspace_dir,
            discovery=self.discovery,
            provenance=self.provenance,
            capabilities=capabilities,
            app_registry=kali_intel.app_registry,
            tool_registry=tool_registry,
        )
        self.dependency_resolver = AutomaticDependencyResolver(
            db=db,
            workspace_dir=workspace_dir,
        )
        self.lifecycle = SoftwareLifecycleManager(
            db=db,
            system_model=kali_intel.system_model,
        )
        self.env_builder = AutonomousEnvironmentBuilder(
            db=db,
            workspace_dir=workspace_dir,
            dep_resolver=self.dependency_resolver,
            system_model=kali_intel.system_model,
        )

        # §229–§234
        self.migration = DevMigrationManager(
            db=db,
            workspace_dir=workspace_dir,
            system_model=kali_intel.system_model,
            pkg_managers=self.pkg_managers,
            lifecycle_mgr=self.lifecycle,
            env_builder=self.env_builder,
        )
        self.backup = OneClickBackupAndRestoreEngine(
            migration_mgr=self.migration,
            workspace_dir=workspace_dir,
        )

    def status_summary(self) -> dict[str, Any]:
        return {
            "sections_implemented": "221-235",
            "unified_architecture": True,
            "supported_acquisition_categories": len(ACQUISITION_22_CATEGORIES),
            "supported_migration_sections": len(MIGRATION_6_SECTIONS),
            "supported_backup_kinds": len(BACKUP_11_KINDS),
            "managed_software_count": len(self.db.list_managed_software(limit=300)),
            "environment_profiles_count": len(self.db.list_environment_profiles()),
            "verified_migration_packages_count": len([p for p in self.db.list_migration_packages(limit=200) if p["verified"]]),
            "quarantined_downloads_count": len(self.db.list_software_quarantines()),
        }
