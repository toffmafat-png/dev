"""§201–§220 Unified ToolRegistry Bindings for the Cybersecurity Engineering Division."""
from __future__ import annotations

import asyncio
from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field

from nova.cyber_division.service import CybersecurityEngineeringDivision
from nova.tools.registry import ToolDefinition, ToolOutcome


class CyberAssessmentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    objective: str = Field(min_length=3, max_length=500)
    target: str = Field(min_length=1, max_length=400)


class CyberPathInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1, max_length=400)


class CyberResearchQueryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    identifier_or_query: str = Field(min_length=2, max_length=200)


class CyberToolFactoryBuildInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=120)
    category: str = Field(default="file_integrity_monitor", max_length=80)
    purpose: str = Field(min_length=4, max_length=400)


class CyberTutorInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    discipline: str = Field(default="linux_security", max_length=80)
    demonstrated_scores: list[float] | None = None


def build_cyber_division_tools(
    service_provider: Callable[[], CybersecurityEngineeringDivision],
) -> list[ToolDefinition]:
    async def _run_engagement(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = CyberAssessmentInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().execute_14_step_security_engagement,
            objective=p.objective,
            target=p.target,
        )
        if not res.get("ok"):
            return ToolOutcome(status="error", summary=str(res.get("reason") or res.get("status")), data=res)
        return ToolOutcome(
            status="success",
            summary=f"Completed 14-step engagement ({res['findings_count']} finding(s), {res['false_positives_count']} FP(s) filtered).",
            data=res,
        )

    async def _analyze_source(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = CyberPathInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(service_provider().code_security.analyze_project, p.path)
        if not res.get("ok"):
            return ToolOutcome(status="error", summary=str(res.get("reason") or res.get("status")), data=res)
        return ToolOutcome(
            status="success",
            summary=f"SAST/SCA inspected `{p.path}`: {res['findings_count']} finding(s).",
            data=res,
        )

    async def _analyze_pcap(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = CyberPathInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(service_provider().network_security.analyze_pcap_file, p.path)
        return ToolOutcome(
            status="success" if res.get("ok") else "error",
            summary=f"Passive PCAP inspection: {res.get('packet_count', 0)} packet(s).",
            data=res,
        )

    async def _inspect_sample(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = CyberPathInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(service_provider().re_forensics.inspect_sample_statically, p.path)
        return ToolOutcome(
            status="success",
            summary=f"Static non-executing inspection of `{res['file_type']}` (sha256={res['hashes']['sha256'][:16]}...).",
            data=res,
        )

    async def _research_cve(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = CyberResearchQueryInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().research_workbench.research_vulnerability,
            p.identifier_or_query,
        )
        if not res.get("ok"):
            return ToolOutcome(status="error", summary=str(res.get("reason") or res.get("status")), data=res)
        return ToolOutcome(
            status="success",
            summary=f"Researched `{res['primary_dossier']['identifier']}` across 8 epistemic fields.",
            data=res,
        )

    async def _build_defensive_tool(args: BaseModel, approved: bool) -> ToolOutcome:
        p = CyberToolFactoryBuildInput.model_validate(args.model_dump())
        if not approved:
            return ToolOutcome(
                status="approval_required",
                summary=f"Building and registering defensive utility `{p.name}` requires explicit operator approval.",
                approval_payload=p.model_dump(),
            )
        res = await asyncio.to_thread(
            service_provider().tool_factory.build_and_register_defensive_tool,
            name=p.name,
            category=p.category,
            purpose=p.purpose,
        )
        return ToolOutcome(
            status="success" if res.get("ok") else "error",
            summary=f"Tool Factory `{p.name}` status={res.get('status', 'validated_and_registered')}.",
            data=res,
        )

    async def _adaptive_tutor(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = CyberTutorInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().expert_tutor.generate_adaptive_module,
            p.discipline,
            demonstrated_scores=p.demonstrated_scores,
        )
        return ToolOutcome(
            status="success",
            summary=f"Adaptive `{res['discipline']}` module at `{res['adapted_level']}` level.",
            data=res,
        )

    return [
        ToolDefinition(
            name="cyber_run_engagement",
            description="Execute the 14-step scope-enforced security assessment, validation, prioritization & reporting pipeline (§202).",
            parameters=CyberAssessmentInput.model_json_schema(),
            input_model=CyberAssessmentInput,
            handler=_run_engagement,
            permission="security_assessment",
            category="cyber_division",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="cyber_analyze_source",
            description="Run non-destructive Python AST SAST, dependency manifest SCA, and Dockerfile audit within registered scope (§208).",
            parameters=CyberPathInput.model_json_schema(),
            input_model=CyberPathInput,
            handler=_analyze_source,
            permission="read_only",
            category="cyber_division",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="cyber_analyze_pcap",
            description="Passively analyze a supplied libpcap (.pcap) packet capture for protocol inventory and cleartext exposure (§206).",
            parameters=CyberPathInput.model_json_schema(),
            input_model=CyberPathInput,
            handler=_analyze_pcap,
            permission="read_only",
            category="cyber_division",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="cyber_inspect_sample_static",
            description="Perform non-executing static inspection (magic type, SHA-256/512, strings, rule signatures) while preserving original evidence (§210).",
            parameters=CyberPathInput.model_json_schema(),
            input_model=CyberPathInput,
            handler=_inspect_sample,
            permission="read_only",
            category="cyber_division",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="cyber_research_vulnerability",
            description="Research published CVE/CWE/advisory entries separating confirmed facts, patches, mitigations, and uncertainties (§209 & §213).",
            parameters=CyberResearchQueryInput.model_json_schema(),
            input_model=CyberResearchQueryInput,
            handler=_research_cve,
            permission="read_only",
            category="cyber_division",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="cyber_factory_build_tool",
            description="Build, AST-audit, sandbox-test, and policy-register a custom defensive security utility (§214).",
            parameters=CyberToolFactoryBuildInput.model_json_schema(),
            input_model=CyberToolFactoryBuildInput,
            handler=_build_defensive_tool,
            permission="security_tool_factory_write",
            category="cyber_division",
            autonomy_class="approval_required",
        ),
        ToolDefinition(
            name="cyber_adaptive_tutor",
            description="Generate an adaptive cybersecurity training module across 17 disciplines tailored to demonstrated performance (§218).",
            parameters=CyberTutorInput.model_json_schema(),
            input_model=CyberTutorInput,
            handler=_adaptive_tutor,
            permission="read_only",
            category="cyber_division",
            autonomy_class="routine",
        ),
    ]
