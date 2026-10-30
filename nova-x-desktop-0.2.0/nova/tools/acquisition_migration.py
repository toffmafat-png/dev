"""§221–§235 Unified ToolRegistry Bindings for Software Acquisition, Environments & Migration."""
from __future__ import annotations

import asyncio
from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field

from nova.acquisition_migration.service import AutonomousAcquisitionAndMigrationService
from nova.tools.registry import ToolDefinition, ToolOutcome


class AcquireSoftwareInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capability_or_name: str = Field(min_length=2, max_length=200)


class ProjectPathInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_dir: str = Field(min_length=1, max_length=400)


class BuildEnvironmentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=120)
    domain: str = Field(default="python_development", max_length=80)
    project_dir: str = Field(min_length=1, max_length=400)
    packages: list[str] | None = None


class EmptyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateBackupInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    backup_kind: str = Field(default="full_backup", max_length=60)


class MigrationArchiveInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    archive_path: str = Field(min_length=1, max_length=400)
    components: list[str] | None = None


def build_acquisition_migration_tools(
    service_provider: Callable[[], AutonomousAcquisitionAndMigrationService],
) -> list[ToolDefinition]:
    async def _acquire(args: BaseModel, approved: bool) -> ToolOutcome:
        p = AcquireSoftwareInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().installer.acquire_verify_and_register,
            p.capability_or_name,
            explicit_operator_approval=approved,
        )
        if not res.get("ok"):
            if res.get("policy_decision", {}).get("prompt_required"):
                return ToolOutcome(
                    status="approval_required",
                    summary=f"Installing `{p.capability_or_name}` requires policy authorization.",
                    approval_payload=res["policy_decision"],
                )
            return ToolOutcome(status="error", summary=str(res.get("status", "failed")), data=res)
        return ToolOutcome(
            status="success",
            summary=f"Provisioned `{p.capability_or_name}` (already_installed={res.get('already_installed')}).",
            data=res,
        )

    async def _resolve_deps(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = ProjectPathInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().dependency_resolver.inspect_and_resolve_project_dependencies,
            p.project_dir,
        )
        return ToolOutcome(
            status="success" if res.get("ok") else "error",
            summary=f"Resolved {len(res.get('resolved_packages', []))} dependency package(s) in isolated env.",
            data=res,
        )

    async def _build_env(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = BuildEnvironmentInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().env_builder.build_working_environment,
            name=p.name,
            domain=p.domain,
            project_dir=p.project_dir,
            packages=p.packages,
        )
        return ToolOutcome(
            status="success" if res.get("ok") else "error",
            summary=f"Built and validated `{p.domain}` environment `{p.name}`.",
            data=res,
        )

    async def _inventory(_args: BaseModel, _approved: bool) -> ToolOutcome:
        res = await asyncio.to_thread(service_provider().lifecycle.generate_software_inventory)
        return ToolOutcome(
            status="success",
            summary=f"Software inventory: {res['managed_software_count']} managed, {res['host_dpkg_package_count']} dpkg.",
            data=res,
        )

    async def _create_backup(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = CreateBackupInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(service_provider().backup.create_verified_backup, p.backup_kind)
        return ToolOutcome(
            status="success" if res.get("ok") else "error",
            summary=f"Created & verified `{p.backup_kind}` migration package.",
            data=res,
        )

    async def _preview_restore(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = MigrationArchiveInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().migration.restore_migration_package,
            p.archive_path,
            components_to_restore=p.components,
            preview_only=True,
        )
        return ToolOutcome(
            status="success" if res.get("ok") else "error",
            summary=f"Restore preview verified for `{p.archive_path}`.",
            data=res,
        )

    async def _restore_archive(args: BaseModel, approved: bool) -> ToolOutcome:
        p = MigrationArchiveInput.model_validate(args.model_dump())
        if not approved:
            return ToolOutcome(
                status="approval_required",
                summary=f"Restoring migration package `{p.archive_path}` requires explicit operator confirmation.",
                approval_payload=p.model_dump(),
            )
        res = await asyncio.to_thread(
            service_provider().migration.restore_migration_package,
            p.archive_path,
            components_to_restore=p.components,
        )
        return ToolOutcome(
            status="success" if res.get("ok") else "error",
            summary=f"Restored components: {res.get('restored_components', [])}.",
            data=res,
        )

    return [
        ToolDefinition(
            name="software_discover_and_acquire",
            description="Discover, provenance-verify, install under standing policy, test, and register software (§221–§226).",
            parameters=AcquireSoftwareInput.model_json_schema(),
            input_model=AcquireSoftwareInput,
            handler=_acquire,
            permission="software_acquisition",
            category="acquisition_migration",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="software_resolve_project_deps",
            description="Detect and resolve missing project dependencies inside an isolated per-project virtual environment (§224).",
            parameters=ProjectPathInput.model_json_schema(),
            input_model=ProjectPathInput,
            handler=_resolve_deps,
            permission="workspace_write",
            category="acquisition_migration",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="software_build_environment",
            description="Prepare and validate a complete isolated development/analysis environment and portable profile (§228).",
            parameters=BuildEnvironmentInput.model_json_schema(),
            input_model=BuildEnvironmentInput,
            handler=_build_env,
            permission="workspace_write",
            category="acquisition_migration",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="software_generate_inventory",
            description="Generate a verified inventory of DEV-managed software and host packages/runtimes (§227).",
            parameters=EmptyInput.model_json_schema(),
            input_model=EmptyInput,
            handler=_inventory,
            permission="read_only",
            category="acquisition_migration",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="migration_create_verified_backup",
            description="Create and cryptographically verify a portable DEV backup or migration package (§229–§232).",
            parameters=CreateBackupInput.model_json_schema(),
            input_model=CreateBackupInput,
            handler=_create_backup,
            permission="workspace_write",
            category="acquisition_migration",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="migration_preview_restore",
            description="Validate an untrusted migration archive and preview hardware compatibility & conflicts safely (§231 & §234).",
            parameters=MigrationArchiveInput.model_json_schema(),
            input_model=MigrationArchiveInput,
            handler=_preview_restore,
            permission="read_only",
            category="acquisition_migration",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="migration_restore_package",
            description="Restore selected or full DEV portable state with automatic pre-restore rollback protection (§231 & §234).",
            parameters=MigrationArchiveInput.model_json_schema(),
            input_model=MigrationArchiveInput,
            handler=_restore_archive,
            permission="migration_restore",
            category="acquisition_migration",
            autonomy_class="approval_required",
        ),
    ]
