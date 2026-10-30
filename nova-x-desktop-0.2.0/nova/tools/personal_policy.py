"""ToolRegistry bindings for DEV Personal-Use Security & Autonomy Policy (Sections 1–7)."""
from __future__ import annotations

import asyncio
from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field

from nova.personal_policy.service import PersonalSecurityAndAutonomyService
from nova.tools.registry import ToolDefinition, ToolOutcome


class EmptyPersonalInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GrantPersistentPermissionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain: str = Field(default="development_tools", max_length=60)
    scope_target: str = Field(min_length=1, max_length=400)
    allowed_programs: list[str] = Field(default_factory=list)
    notes: str = Field(default="", max_length=300)


class GuardedFileOpInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_path: str = Field(min_length=1, max_length=400)
    operation: str = Field(default="overwrite", max_length=20)
    new_content: str = Field(default="", max_length=100_000)


class RegisterCyberLabInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=140)
    category: str = Field(default="development_environment", max_length=60)
    targets: list[str] = Field(min_length=1)


def build_personal_policy_tools(
    service_provider: Callable[[], PersonalSecurityAndAutonomyService],
) -> list[ToolDefinition]:
    async def _status(_args: BaseModel, _approved: bool) -> ToolOutcome:
        svc = service_provider()
        data = {
            "status": svc.status_summary(),
            "manifest": svc.policy_manifest(),
            "active_grants": svc.db.list_personal_persistent_grants(active_only=True),
        }
        return ToolOutcome(
            status="success",
            summary=f"Personal policy mode={data['status']['profile_mode']} ({data['status']['active_persistent_grants_count']} active grants).",
            data=data,
        )

    async def _grant(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = GrantPersistentPermissionInput.model_validate(args.model_dump())
        saved = await asyncio.to_thread(
            service_provider().autonomy.grant_persistent_permission,
            domain=p.domain,
            scope_target=p.scope_target,
            allowed_programs=p.allowed_programs,
            notes=p.notes,
        )
        return ToolOutcome(
            status="success",
            summary=f"Saved persistent grant `{saved['grant_id']}` for domain `{p.domain}`.",
            data=saved,
        )

    async def _guarded_file(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = GuardedFileOpInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().safeguards.guarded_file_operation,
            p.target_path,
            operation=p.operation,
            new_content=p.new_content,
        )
        status = "success" if res.get("ok") else "denied"
        return ToolOutcome(
            status=status,
            summary=f"Guarded {p.operation} on `{p.target_path}` (backup_id={res.get('backup_id') or 'none'}).",
            data=res,
        )

    async def _register_lab(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = RegisterCyberLabInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().cyber_research.register_persistent_lab_environment,
            name=p.name,
            category=p.category,
            targets=p.targets,
        )
        return ToolOutcome(
            status="success",
            summary=f"Registered persistent personal cyber lab `{p.name}`.",
            data=res,
        )

    async def _transfers(_args: BaseModel, _approved: bool) -> ToolOutcome:
        res = service_provider().local_privacy.inspect_external_transfers()
        return ToolOutcome(
            status="success",
            summary=f"Logged {res['transfer_count']} external transfer(s) ({res['blocked_count']} blocked).",
            data=res,
        )

    return [
        ToolDefinition(
            name="personal_policy_status",
            description="Inspect DEV's single-user personal security & autonomy policy, domains, and persistent grants.",
            parameters=EmptyPersonalInput.model_json_schema(),
            input_model=EmptyPersonalInput,
            handler=_status,
            permission="workspace_read",
            category="personal_policy",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="personal_grant_permission",
            description="Configure a persistent permission grant for trusted recurring commands/files in an owned scope.",
            parameters=GrantPersistentPermissionInput.model_json_schema(),
            input_model=GrantPersistentPermissionInput,
            handler=_grant,
            permission="workspace_write",
            category="personal_policy",
            autonomy_class="approval_required",
        ),
        ToolDefinition(
            name="personal_guarded_file_op",
            description="Perform a risk-proportionate file overwrite or delete with automatic SHA-256 rollback backup.",
            parameters=GuardedFileOpInput.model_json_schema(),
            input_model=GuardedFileOpInput,
            handler=_guarded_file,
            permission="workspace_write",
            category="personal_policy",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="personal_register_cyber_lab",
            description="Register an owned/authorized personal cybersecurity testing environment with persistent authorization.",
            parameters=RegisterCyberLabInput.model_json_schema(),
            input_model=RegisterCyberLabInput,
            handler=_register_lab,
            permission="workspace_write",
            category="personal_policy",
            autonomy_class="approval_required",
        ),
        ToolDefinition(
            name="personal_inspect_transfers",
            description="Inspect visible external AI provider data transfers and local-only project protections.",
            parameters=EmptyPersonalInput.model_json_schema(),
            input_model=EmptyPersonalInput,
            handler=_transfers,
            permission="workspace_read",
            category="personal_policy",
            autonomy_class="routine",
        ),
    ]
