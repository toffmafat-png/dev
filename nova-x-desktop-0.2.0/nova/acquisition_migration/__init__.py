"""Autonomous Software Acquisition, Environment Management & Universal Migration Engine (§221–§235)."""
from __future__ import annotations

from nova.acquisition_migration.crypto_and_archive import (
    MIGRATION_FORMAT_VERSION,
    ArchiveSecurityError,
    MigrationVaultCipher,
    UniversalMigrationArchiveCodec,
)
from nova.acquisition_migration.discovery_and_provenance import (
    ACQUISITION_22_CATEGORIES,
    PROVENANCE_13_INSPECTION_FIELDS,
    TRUST_CHANNEL_5_TIERS,
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
from nova.acquisition_migration.service import AutonomousAcquisitionAndMigrationService

__all__ = [
    "ACQUISITION_22_CATEGORIES",
    "BACKUP_11_KINDS",
    "MIGRATION_6_SECTIONS",
    "MIGRATION_FORMAT_VERSION",
    "PROVENANCE_13_INSPECTION_FIELDS",
    "TRUST_CHANNEL_5_TIERS",
    "ArchiveSecurityError",
    "AutomaticDependencyResolver",
    "AutonomousAcquisitionAndMigrationService",
    "AutonomousEnvironmentBuilder",
    "AutonomousInstallationController",
    "DevMigrationManager",
    "IntelligentSoftwareDiscoveryEngine",
    "MigrationVaultCipher",
    "OneClickBackupAndRestoreEngine",
    "SoftwareLifecycleManager",
    "SoftwareProvenanceVerifier",
    "UniversalMigrationArchiveCodec",
    "UniversalPackageManagerDiscovery",
]
