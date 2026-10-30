"""ToolRegistry bindings for §261–§275 Next-Generation Autonomous Cyber Intelligence Engine."""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from nova.cyber_intelligence.service import NextGenCyberIntelligenceService
from nova.tools.registry import ToolDefinition, ToolOutcome


class EmptyCyberIntelInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UnknownInvestigateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    problem_statement: str = Field(min_length=3, max_length=1000)
    domain_kind: str = Field(default="unfamiliar_protocol", max_length=80)
    artifact_text: str = Field(default="", max_length=32_000)


class VulnLabAnalyzeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_component: str = Field(min_length=2, max_length=200)
    source_text: str = Field(min_length=1, max_length=32_000)
    patched_text: str = Field(default="", max_length=32_000)


class InventSecurityToolInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=120)
    category: str = Field(default="configuration_auditor", max_length=80)
    capability_gap: str = Field(min_length=4, max_length=500)


class SecurityMissionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    objective: str = Field(min_length=4, max_length=800)
    targets: list[dict[str, Any]] = Field(min_length=1, max_length=20)


class BenchmarkRunInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    split: str = Field(default="default", max_length=24)
    save_as_baseline: bool = False


def build_cyber_intelligence_tools(
    service_provider: Callable[[], NextGenCyberIntelligenceService],
) -> list[ToolDefinition]:
    async def _status(_args: BaseModel, _approved: bool) -> ToolOutcome:
        svc = service_provider()
        data = {
            "status": svc.status_summary(),
            "manifest": svc.capability_manifest(),
        }
        return ToolOutcome(
            status="success",
            summary=f"Cyber Intelligence (§261–§275) active: {data['status']['invented_tools_count']} invented tool(s), {data['status']['vuln_lab_cases_count']} lab case(s).",
            data=data,
        )

    async def _investigate(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = UnknownInvestigateInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().unknown_mastery.investigate_unknown_problem,
            problem_statement=p.problem_statement,
            domain_kind=p.domain_kind,
            artifact_text=p.artifact_text,
        )
        return ToolOutcome(
            status="success",
            summary=f"Completed 15-step unknown-problem investigation `{res['investigation_id']}` -> `{res['status']}`.",
            data=res,
        )

    async def _vuln_lab(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = VulnLabAnalyzeInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().vuln_lab.analyze_artifact_in_isolated_lab,
            target_component=p.target_component,
            source_text=p.source_text,
            patched_text=p.patched_text,
        )
        return ToolOutcome(
            status="success",
            summary=f"Analyzed `{p.target_component}` in isolated vulnerability lab (`{res['case_id']}`).",
            data=res,
        )

    async def _invent_tool(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = InventSecurityToolInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().tool_inventor.invent_security_tool,
            name=p.name,
            category=p.category,
            capability_gap=p.capability_gap,
        )
        return ToolOutcome(
            status="success",
            summary=f"Invented & validated `{res['name']}` v{res['version']} (`{res['tool_id']}`).",
            data=res,
        )

    async def _mission(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = SecurityMissionInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().mission_system.execute_mission,
            objective=p.objective,
            targets=p.targets,
        )
        return ToolOutcome(
            status="success",
            summary=f"Executed 12-stage mission `{res['mission_id']}` ({len(res['subtasks'])} completed, {len(res['isolated_subtasks'])} isolated).",
            data=res,
        )

    async def _benchmark(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = BenchmarkRunInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().benchmarks.run_suite,
            split=p.split,
            save_as_baseline=p.save_as_baseline,
        )
        return ToolOutcome(
            status="success",
            summary=f"Benchmark `{res['run_id']}` ({p.split}) accuracy={res['metrics']['technical_accuracy']}.",
            data=res,
        )

    return [
        ToolDefinition(
            name="cyber_intel_status",
            description="Inspect §261–§275 Next-Generation Autonomous Cyber Intelligence Engine status and capabilities.",
            parameters=EmptyCyberIntelInput.model_json_schema(),
            input_model=EmptyCyberIntelInput,
            handler=_status,
            permission="workspace_read",
            category="cyber_intelligence",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="cyber_intel_investigate_unknown",
            description="Run §261 15-step scientific investigation on an unfamiliar protocol, code, OS, or security challenge.",
            parameters=UnknownInvestigateInput.model_json_schema(),
            input_model=UnknownInvestigateInput,
            handler=_investigate,
            permission="workspace_read",
            category="cyber_intelligence",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="cyber_intel_vuln_lab_analyze",
            description="Run §262 isolated vulnerability research analysis, patch diff verification, and report generation.",
            parameters=VulnLabAnalyzeInput.model_json_schema(),
            input_model=VulnLabAnalyzeInput,
            handler=_vuln_lab,
            permission="workspace_read",
            category="cyber_intelligence",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="cyber_intel_invent_tool",
            description="Run §265 12-step autonomous security tool invention, testing, static audit, and registration.",
            parameters=InventSecurityToolInput.model_json_schema(),
            input_model=InventSecurityToolInput,
            handler=_invent_tool,
            permission="workspace_write",
            category="cyber_intelligence",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="cyber_intel_run_mission",
            description="Coordinate a §269 12-stage autonomous security mission within registered scopes.",
            parameters=SecurityMissionInput.model_json_schema(),
            input_model=SecurityMissionInput,
            handler=_mission,
            permission="workspace_write",
            category="cyber_intelligence",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="cyber_intel_run_benchmark",
            description="Run §272 12-metric deterministic cybersecurity benchmark suite.",
            parameters=BenchmarkRunInput.model_json_schema(),
            input_model=BenchmarkRunInput,
            handler=_benchmark,
            permission="workspace_read",
            category="cyber_intelligence",
            autonomy_class="routine",
        ),
    ]
