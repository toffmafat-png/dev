"""§181–§200 Unified ToolRegistry Definitions for Kali Linux Intelligence,
Tool Discovery & Execution, Automatic Documentation, Application Mastery,
Cybersecurity Labs, Kali Training Mode, and Host Troubleshooting.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field

from nova.kali_intel.service import KaliIntelligenceService
from nova.tools.registry import ToolDefinition, ToolOutcome


class KaliSystemInspectInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    force_refresh: bool = False


class KaliToolSearchInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    objective: str = Field(min_length=1, max_length=500)
    category: str = Field(default="", max_length=100)
    protocol: str = Field(default="", max_length=60)
    installed_only: bool = False


class KaliToolNameInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)


class KaliExecuteObjectiveInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    objective: str = Field(min_length=2, max_length=500)
    explicit_argv: list[str] | None = None


class KaliCapabilityQueryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=3, max_length=500)


class KaliLearnProgramInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command_or_path: str = Field(min_length=1, max_length=300)
    safe_test_args: list[str] | None = None


class KaliTroubleshootInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    symptom_or_domain: str = Field(min_length=2, max_length=500)


class KaliTrainingInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    track: str = Field(default="kali_fundamentals", max_length=80)
    level: str = Field(default="beginner", max_length=24)


class KaliLabCreateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=160)
    purpose: str = Field(min_length=4, max_length=500)
    requested_ram_mb: int = Field(default=256, ge=32, le=8192)
    network_scope: str = Field(default="127.0.0.1/32", max_length=80)


def build_kali_intel_tools(
    service_provider: Callable[[], KaliIntelligenceService],
) -> list[ToolDefinition]:
    async def _inspect_system(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = KaliSystemInspectInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().system_model.get_or_refresh_model,
            force_refresh=p.force_refresh,
        )
        dist = res["model"]["distribution"]["pretty_name"]
        ktools = res["model"]["installed_kali_tools"]["count"]
        return ToolOutcome(
            status="success",
            summary=f"Inspected live environment ({dist}); {ktools} reference Kali CLI utilities installed.",
            data=res,
        )

    async def _search_tools(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = KaliToolSearchInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().tool_engine.search_tools_for_objective,
            p.objective,
            category=p.category,
            protocol=p.protocol,
            installed_only=p.installed_only,
        )
        return ToolOutcome(
            status="success",
            summary=res["recommendation_rationale"],
            data=res,
        )

    async def _tool_profile(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = KaliToolNameInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().tool_engine.build_tool_profile,
            p.name,
        )
        return ToolOutcome(
            status="success",
            summary=f"Built 20-field Kali profile for `{p.name}` (status={res['installation_status']}).",
            data=res,
        )

    async def _retrieve_docs(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = KaliToolNameInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().doc_engine.retrieve_prioritized_documentation,
            p.name,
        )
        return ToolOutcome(
            status="success",
            summary=f"Retrieved {len(res['sources'])} prioritized documentation sources for `{p.name}`.",
            data=res,
        )

    async def _execute_objective(args: BaseModel, approved: bool) -> ToolOutcome:
        p = KaliExecuteObjectiveInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().tool_executor.execute_13_step_objective,
            p.objective,
            explicit_argv=p.explicit_argv,
            approved=approved,
        )
        if res.get("status") == "approval_required":
            return ToolOutcome(
                status="approval_required",
                summary=f"Execution of `{res.get('selected_tool')}` requires explicit approval.",
                approval_payload={"planned_argv": res.get("planned_argv")},
            )
        return ToolOutcome(
            status="success" if res.get("ok") else "error",
            summary=str(res.get("explanation") or res.get("status")),
            data=res,
        )

    async def _query_capability(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = KaliCapabilityQueryInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().app_registry.query_capabilities,
            p.question,
        )
        return ToolOutcome(
            status="success",
            summary=f"Capability `{res['matched_capability_domain']}`: {len(res['installed_capable_tools'])} installed tool(s).",
            data=res,
        )

    async def _learn_program(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = KaliLearnProgramInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().program_learner.learn_unfamiliar_program,
            p.command_or_path,
            safe_test_args=p.safe_test_args,
        )
        return ToolOutcome(
            status="success" if res.get("ok") else "error",
            summary=(
                f"Learned `{res['program']}`: {len(res['known_functionality'])} known, "
                f"{len(res['inferred_functionality'])} inferred, {len(res['tested_functionality'])} tested."
            ),
            data=res,
        )

    async def _troubleshoot(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = KaliTroubleshootInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().troubleshooter.diagnose_13_steps,
            p.symptom_or_domain,
        )
        return ToolOutcome(
            status="success",
            summary=f"Diagnosed `{res['classified_domain']}` across 13 host-verified steps.",
            data=res,
        )

    async def _training_lesson(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = KaliTrainingInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().training_academy.generate_lesson,
            p.track,
            level=p.level,
        )
        return ToolOutcome(
            status="success",
            summary=f"Generated Kali Training lesson `{res['title']}` ({res['level']}).",
            data=res,
        )

    async def _create_lab(args: BaseModel, approved: bool) -> ToolOutcome:
        p = KaliLabCreateInput.model_validate(args.model_dump())
        if not approved:
            return ToolOutcome(
                status="approval_required",
                summary=f"Provisioning isolated cybersecurity lab `{p.name}` requires explicit approval.",
                approval_payload=p.model_dump(),
            )
        res = await asyncio.to_thread(
            service_provider().lab_manager.create_isolated_lab,
            name=p.name,
            purpose=p.purpose,
            requested_ram_mb=p.requested_ram_mb,
            network_scope=p.network_scope,
        )
        return ToolOutcome(
            status="success" if res.get("ok") else "error",
            summary=f"Cyber lab `{p.name}` status: {res['lab']['status'] if res.get('ok') else res.get('status')}",
            data=res,
        )

    return [
        ToolDefinition(
            name="kali_inspect_system",
            description="Inspect all 21 live Kali/Linux system dimensions (distro, kernel, packages, repos, hardware, services, permissions, containers, policies; §181).",
            parameters=KaliSystemInspectInput.model_json_schema(),
            input_model=KaliSystemInspectInput,
            handler=_inspect_system,
            permission="read_only",
            category="kali_intel",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="kali_search_tools",
            description="Discover and compare Kali/Linux tools by natural-language problem, protocol, or category while checking real host installation status (§182).",
            parameters=KaliToolSearchInput.model_json_schema(),
            input_model=KaliToolSearchInput,
            handler=_search_tools,
            permission="read_only",
            category="kali_intel",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="kali_tool_profile",
            description="Build a complete 20-field Kali tool profile grounded in live executable, dpkg/apt, --help, and man-page state (§182).",
            parameters=KaliToolNameInput.model_json_schema(),
            input_model=KaliToolNameInput,
            handler=_tool_profile,
            permission="read_only",
            category="kali_intel",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="kali_retrieve_docs",
            description="Retrieve and index documentation across the 5-tier authority hierarchy (P1 local man/--help -> P5 community; §184 & §191).",
            parameters=KaliToolNameInput.model_json_schema(),
            input_model=KaliToolNameInput,
            handler=_retrieve_docs,
            permission="read_only",
            category="kali_intel",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="kali_execute_objective",
            description="Run the §183 13-step tool discovery, help-flag verification, and permission-gated execution workflow without inventing CLI options.",
            parameters=KaliExecuteObjectiveInput.model_json_schema(),
            input_model=KaliExecuteObjectiveInput,
            handler=_execute_objective,
            permission="tool_execution",
            category="kali_intel",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="kali_query_capability",
            description="Search the live Capability Registry for installed applications able to handle a task or file format (§186 & §196).",
            parameters=KaliCapabilityQueryInput.model_json_schema(),
            input_model=KaliCapabilityQueryInput,
            handler=_query_capability,
            permission="read_only",
            category="kali_intel",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="kali_learn_program",
            description="Learn an unfamiliar local program across 12 steps, separating known, inferred, and sandbox-tested functionality (§194).",
            parameters=KaliLearnProgramInput.model_json_schema(),
            input_model=KaliLearnProgramInput,
            handler=_learn_program,
            permission="read_only",
            category="kali_intel",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="kali_troubleshoot_host",
            description="Execute the 13-step Kali Linux diagnostic workflow across 19 failure classes using non-destructive host probes (§193).",
            parameters=KaliTroubleshootInput.model_json_schema(),
            input_model=KaliTroubleshootInput,
            handler=_troubleshoot,
            permission="read_only",
            category="kali_intel",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="kali_training_lesson",
            description="Generate a structured Kali Training lesson, practical exercise, flashcards, and quiz with clear source attribution (§192).",
            parameters=KaliTrainingInput.model_json_schema(),
            input_model=KaliTrainingInput,
            handler=_training_lesson,
            permission="read_only",
            category="kali_intel",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="kali_cyber_lab_create",
            description="Provision a hardware-checked, network-isolated cybersecurity training lab with baseline snapshot (§189).",
            parameters=KaliLabCreateInput.model_json_schema(),
            input_model=KaliLabCreateInput,
            handler=_create_lab,
            permission="lab_write",
            category="kali_intel",
            autonomy_class="approval_required",
        ),
    ]
