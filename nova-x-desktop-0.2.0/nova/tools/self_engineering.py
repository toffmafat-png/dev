"""ToolRegistry bindings for §276–§295 Autonomous Architecture, Source Code Evolution & Self-Engineering Engine."""
from __future__ import annotations

import asyncio
from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field

from nova.self_engineering.service import SelfEngineeringService
from nova.tools.registry import ToolDefinition, ToolOutcome


class EmptySelfEngInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SelfEngArchAnalysisInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    module_for_impact: str = Field(default="", max_length=200)


class SelfEngObjectiveInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    objective: str = Field(min_length=4, max_length=1500)


def build_self_engineering_tools(
    service_provider: Callable[[], SelfEngineeringService],
) -> list[ToolDefinition]:
    async def _inspect_repo(_args: BaseModel, _approved: bool) -> ToolOutcome:
        rep = await asyncio.to_thread(service_provider().source_intel.inspect_complete_repository)
        return ToolOutcome(
            status="success",
            summary=f"Inspected live repository across {len(rep['understood_domains'])} domains ({rep['summary_counts']['modules']} modules, {rep['summary_counts']['tests']} tests).",
            data=rep["summary_counts"],
        )

    async def _arch_analysis(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = SelfEngArchAnalysisInput.model_validate(args.model_dump())
        svc = service_provider()
        arch = await asyncio.to_thread(svc.arch_analyzer.analyze_architecture)
        impact = (
            await asyncio.to_thread(svc.knowledge_graph.estimate_change_impact, p.module_for_impact)
            if p.module_for_impact
            else None
        )
        return ToolOutcome(
            status="success",
            summary=f"Completed 16-dimension live architecture analysis ({len(arch['evaluated_dimensions'])} dimensions).",
            data={"architecture_summary": arch["summary"], "impact_estimate": impact},
        )

    async def _audit_deps(_args: BaseModel, _approved: bool) -> ToolOutcome:
        deps = await asyncio.to_thread(service_provider().dep_intel.audit_dependencies)
        return ToolOutcome(
            status="success",
            summary=f"Audited dependencies across 10 dimensions (healthy={deps['healthy']}).",
            data=deps,
        )

    async def _execute_objective(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = SelfEngObjectiveInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().engineering_assistant.execute_engineering_objective,
            objective=p.objective,
        )
        return ToolOutcome(
            status="success",
            summary=f"Completed 14-step engineering workflow (`{res['adr']['adr_id']}`).",
            data=res,
        )

    return [
        ToolDefinition(
            name="self_eng_inspect_repository",
            description="Inspect DEV's own live repository across all 20 architectural domains (§277).",
            parameters=EmptySelfEngInput.model_json_schema(),
            input_model=EmptySelfEngInput,
            handler=_inspect_repo,
            permission="workspace_read",
            category="self_engineering",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="self_eng_architecture_analysis",
            description="Run §278/§289 16-dimension architectural analysis and live knowledge-graph impact estimation.",
            parameters=SelfEngArchAnalysisInput.model_json_schema(),
            input_model=SelfEngArchAnalysisInput,
            handler=_arch_analysis,
            permission="workspace_read",
            category="self_engineering",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="self_eng_audit_dependencies",
            description="Run §291 10-dimension Python dependency health audit and generate CycloneDX-lite SBOM.",
            parameters=EmptySelfEngInput.model_json_schema(),
            input_model=EmptySelfEngInput,
            handler=_audit_deps,
            permission="workspace_read",
            category="self_engineering",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="self_eng_execute_objective",
            description="Run §290 14-step Autonomous Engineering Assistant on a high-level software objective.",
            parameters=SelfEngObjectiveInput.model_json_schema(),
            input_model=SelfEngObjectiveInput,
            handler=_execute_objective,
            permission="workspace_write",
            category="self_engineering",
            autonomy_class="routine",
        ),
    ]
