"""Schema-validated ToolRegistry bindings for the NOVA X Universal Creation Engine (§116–§148)."""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from nova.tools.registry import ToolDefinition, ToolOutcome

if TYPE_CHECKING:
    from nova.creation.engine import UniversalCreationEngine


class CreationDiscoverInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain: str = Field(default="", max_length=64, description="Optional creation domain filter")
    refresh: bool = Field(default=False, description="Force re-probing host binaries and modules")


class CreationBuildInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    prompt: str = Field(min_length=3, max_length=2000, description="Natural-language creation request")
    name: str = Field(default="", max_length=120, description="Optional explicit project title")
    domain: str = Field(default="", max_length=64, description="Optional domain override")
    package: bool = Field(default=True, description="Package deliverable into handover archive after QA")


class CreationCommandInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: str = Field(min_length=3, max_length=2000, description="Natural-language §145 creation command")
    project_id: str = Field(default="", max_length=80)


class CreationConvertInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_rel_path: str = Field(min_length=1, max_length=400, description="Workspace-relative input file path")
    target_rel_path: str = Field(min_length=1, max_length=400, description="Workspace-relative output file path")


def build_creation_tools(engine_getter: Callable[[], UniversalCreationEngine]) -> list[ToolDefinition]:
    async def _discover(args: BaseModel, _approved: bool) -> ToolOutcome:
        parsed: CreationDiscoverInput = args  # type: ignore[assignment]
        eng = engine_getter()
        disc = eng.discovery.discover(refresh=parsed.refresh)
        if parsed.domain:
            tc = eng.toolchains.select_toolchain(parsed.domain)
            return ToolOutcome("success", f"Discovered toolchain for domain '{parsed.domain}'.", {"toolchain": tc, "formats": disc["processable_formats"]})
        return ToolOutcome(
            "success",
            f"Discovered {len(disc['installed_applications'])} installed host tool(s) across {len(disc['local_runnable_domains'])} domain(s).",
            {
                "local_runnable_domains": disc["local_runnable_domains"],
                "installed_applications": [a["id"] for a in disc["installed_applications"]],
                "processable_formats": disc["processable_formats"],
            },
        )

    async def _build(args: BaseModel, _approved: bool) -> ToolOutcome:
        parsed: CreationBuildInput = args  # type: ignore[assignment]
        eng = engine_getter()
        try:
            report = await eng.create_from_intent(
                parsed.prompt,
                name=parsed.name,
                domain_override=parsed.domain,
                package=parsed.package,
            )
        except Exception as exc:
            return ToolOutcome("error", f"Creation failed: {exc}")
        return ToolOutcome(
            "success",
            f"Created '{report['name']}' ({report['domain']}) status={report['status']} QA={report['qa']['quality_score']}.",
            {
                "project_id": report["project_id"],
                "domain": report["domain"],
                "status": report["status"],
                "project_dir": report["project_dir"],
                "primary_artifacts": report["primary_artifacts"],
                "qa_passed": report["qa"]["passed"],
                "limitations": report["limitations"],
            },
        )

    async def _command(args: BaseModel, _approved: bool) -> ToolOutcome:
        parsed: CreationCommandInput = args  # type: ignore[assignment]
        eng = engine_getter()
        try:
            out = await eng.resolve_command(parsed.command, project_id=parsed.project_id)
        except Exception as exc:
            return ToolOutcome("error", str(exc))
        return ToolOutcome("success", f"Resolved creation command ({out.get('command_kind')}).", out)

    async def _convert(args: BaseModel, _approved: bool) -> ToolOutcome:
        parsed: CreationConvertInput = args  # type: ignore[assignment]
        eng = engine_getter()
        ws = eng.workspace_root.resolve()
        src = (ws / parsed.source_rel_path).resolve()
        dst = (ws / parsed.target_rel_path).resolve()
        if not src.is_relative_to(ws) or not dst.is_relative_to(ws):
            return ToolOutcome("denied", "Conversion paths must stay inside the approved workspace directory.")
        if dst.exists() and not _approved:
            return ToolOutcome("approval_required", f"Target '{Path(parsed.target_rel_path)}' already exists; approval required to overwrite.")
        res = eng.converter.convert(src, dst)
        if not res.get("converted"):
            return ToolOutcome("error", str(res.get("error", "Conversion failed.")), res)
        return ToolOutcome("success", f"Converted {parsed.source_rel_path} -> {parsed.target_rel_path}.", res)

    return [
        ToolDefinition(
            name="creation.discover",
            description="Inspect installed creation tools, supported file formats, and domain toolchains on this machine.",
            parameters={
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "maxLength": 64},
                    "refresh": {"type": "boolean"},
                },
                "additionalProperties": False,
            },
            input_model=CreationDiscoverInput,
            handler=_discover,
            permission="workspace.read",
            category="creation",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="creation.build",
            description="Turn a natural-language specification into a tested, QA-verified digital deliverable inside a new workspace project folder.",
            parameters={
                "type": "object",
                "required": ["prompt"],
                "properties": {
                    "prompt": {"type": "string", "minLength": 3, "maxLength": 2000},
                    "name": {"type": "string", "maxLength": 120},
                    "domain": {"type": "string", "maxLength": 64},
                    "package": {"type": "boolean"},
                },
                "additionalProperties": False,
            },
            input_model=CreationBuildInput,
            handler=_build,
            permission="workspace.write",
            category="creation",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="creation.command",
            description="Execute a §145 natural-language creation studio command (prototype, reusable check, blueprint, compare, continue).",
            parameters={
                "type": "object",
                "required": ["command"],
                "properties": {
                    "command": {"type": "string", "minLength": 3, "maxLength": 2000},
                    "project_id": {"type": "string", "maxLength": 80},
                },
                "additionalProperties": False,
            },
            input_model=CreationCommandInput,
            handler=_command,
            permission="workspace.write",
            category="creation",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="creation.convert",
            description="Safely convert a workspace file between supported formats while preserving the source file and reporting any information loss.",
            parameters={
                "type": "object",
                "required": ["source_rel_path", "target_rel_path"],
                "properties": {
                    "source_rel_path": {"type": "string", "minLength": 1, "maxLength": 400},
                    "target_rel_path": {"type": "string", "minLength": 1, "maxLength": 400},
                },
                "additionalProperties": False,
            },
            input_model=CreationConvertInput,
            handler=_convert,
            permission="workspace.write",
            category="creation",
            autonomy_class="routine",
        ),
    ]


__all__ = ["build_creation_tools"]
