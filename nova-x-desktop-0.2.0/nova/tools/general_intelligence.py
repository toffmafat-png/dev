"""§236–§260 Unified ToolRegistry Bindings for General Intelligence, Cognitive Architecture & Expansion."""
from __future__ import annotations

import asyncio
from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field

from nova.general_intelligence.service import GeneralIntelligenceService
from nova.tools.registry import ToolDefinition, ToolOutcome


class CognitiveCycleInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    objective: str = Field(min_length=3, max_length=500)
    context_id: str = Field(default="default", max_length=80)


class MemoryRecordInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    layer: str = Field(default="semantic_memory", max_length=60)
    subject: str = Field(min_length=2, max_length=200)
    content: str = Field(min_length=2, max_length=2000)
    attribute_key: str = Field(default="", max_length=120)
    claim_origin: str = Field(default="direct_user_statement", max_length=60)
    source_ref: str = Field(default="", max_length=300)


class WorldPredictInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_entity_id: str = Field(min_length=2, max_length=120)
    proposed_action: str = Field(min_length=2, max_length=240)


class DatasetInspectInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dataset_path: str = Field(min_length=1, max_length=400)
    x_col: str = Field(default="", max_length=80)
    y_col: str = Field(default="", max_length=80)


class UntrustedScanInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=10000)
    source: str = Field(default="external_document", max_length=160)


class OptimizePlanInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task_signature: str = Field(min_length=2, max_length=140)
    complexity: str = Field(default="moderate", max_length=40)
    available_ram_mb: int = Field(default=4096, ge=256, le=1_048_576)


class EmptyGIInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


def build_general_intelligence_tools(
    service_provider: Callable[[], GeneralIntelligenceService],
) -> list[ToolDefinition]:
    async def _cognitive_cycle(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = CognitiveCycleInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().cognitive_arch.run_coordinated_cycle,
            context_id=p.context_id,
            objective=p.objective,
        )
        return ToolOutcome(
            status="success",
            summary=f"Coordinated 11-subsystem cognitive cycle v{res['state_version']} for '{p.objective[:60]}'.",
            data=res,
        )

    async def _record_memory(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = MemoryRecordInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().memory_engine.record_memory,
            layer=p.layer,
            subject=p.subject,
            content=p.content,
            attribute_key=p.attribute_key,
            claim_origin=p.claim_origin,
            source_ref=p.source_ref,
        )
        return ToolOutcome(
            status="success",
            summary=f"Recorded [{p.layer}] memory '{p.subject}' (contradictions={len(res['contradictions'])}).",
            data=res,
        )

    async def _predict_world_impact(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = WorldPredictInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().world_model.predict_action_side_effects,
            p.target_entity_id,
            p.proposed_action,
        )
        return ToolOutcome(
            status="success",
            summary=f"Predicted impact on `{p.target_entity_id}`: risk={res['risk_level']} ({len(res['impacted_dependents'])} dependent(s)).",
            data=res,
        )

    async def _investigate_dataset(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = DatasetInspectInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().research_lab.investigate_dataset,
            p.dataset_path,
            x_col=p.x_col,
            y_col=p.y_col,
        )
        return ToolOutcome(
            status="success",
            summary=f"Investigated dataset `{p.dataset_path}` ({res['dataset_provenance']['row_count']} rows).",
            data=res,
        )

    async def _scan_untrusted(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = UntrustedScanInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().ai_security.inspect_untrusted_content,
            p.text,
            source=p.source,
        )
        return ToolOutcome(
            status="success",
            summary=f"Inspected `{p.source}`: safe={res['safe']} (findings={len(res['findings'])}).",
            data=res,
        )

    async def _optimize_plan(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = OptimizePlanInput.model_validate(args.model_dump())
        res = await asyncio.to_thread(
            service_provider().expansion_hub.select_optimal_execution_plan,
            task_signature=p.task_signature,
            complexity=p.complexity,
            available_ram_mb=p.available_ram_mb,
        )
        return ToolOutcome(
            status="success",
            summary=f"Selected execution plan (cache_hit={res['cache_hit']}).",
            data=res,
        )

    async def _capability_roadmap(_args: BaseModel, _approved: bool) -> ToolOutcome:
        res = await asyncio.to_thread(
            service_provider().expansion_hub.get_living_capability_roadmap,
        )
        return ToolOutcome(
            status="success",
            summary=f"Capability roadmap: {len(res['current_abilities'])} active abilities.",
            data=res,
        )

    return [
        ToolDefinition(
            name="gi_cognitive_cycle",
            description="Run a coordinated 11-subsystem cognitive cycle over shared versioned context (§236).",
            parameters=CognitiveCycleInput.model_json_schema(),
            input_model=CognitiveCycleInput,
            handler=_cognitive_cycle,
            permission="workspace_read",
            category="general_intelligence",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="gi_record_multilayer_memory",
            description="Record provenance-tracked memory across 11 cognitive layers with contradiction detection (§237, §256).",
            parameters=MemoryRecordInput.model_json_schema(),
            input_model=MemoryRecordInput,
            handler=_record_memory,
            permission="workspace_write",
            category="general_intelligence",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="gi_predict_world_impact",
            description="Predict downstream side effects and dependencies in the 15-domain world model before acting (§238).",
            parameters=WorldPredictInput.model_json_schema(),
            input_model=WorldPredictInput,
            handler=_predict_world_impact,
            permission="workspace_read",
            category="general_intelligence",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="gi_investigate_dataset",
            description="Run statistical, outlier, correlation, and provenance analysis on a CSV/JSON dataset (§245).",
            parameters=DatasetInspectInput.model_json_schema(),
            input_model=DatasetInspectInput,
            handler=_investigate_dataset,
            permission="workspace_read",
            category="general_intelligence",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="gi_inspect_untrusted_document",
            description="Scan untrusted text/documents for OWASP GenAI prompt injection and privilege escalation (§253).",
            parameters=UntrustedScanInput.model_json_schema(),
            input_model=UntrustedScanInput,
            handler=_scan_untrusted,
            permission="workspace_read",
            category="general_intelligence",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="gi_optimize_compute_and_cost",
            description="Select cost- and resource-optimal model/worker execution plan with verified caching (§258).",
            parameters=OptimizePlanInput.model_json_schema(),
            input_model=OptimizePlanInput,
            handler=_optimize_plan,
            permission="workspace_read",
            category="general_intelligence",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="gi_living_capability_roadmap",
            description="Inspect DEV's living 10-section knowledge and capability roadmap (§259).",
            parameters=EmptyGIInput.model_json_schema(),
            input_model=EmptyGIInput,
            handler=_capability_roadmap,
            permission="workspace_read",
            category="general_intelligence",
            autonomy_class="routine",
        ),
    ]
