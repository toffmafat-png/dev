"""Unified service facade & scoped tool registration for DEV Corrected Master Architecture (§1–§11)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from nova.config import Settings
from nova.db import Database
from nova.hybrid_cloud.architecture import (
    HYBRID_INVARIANTS,
    LlamaCppFallbackAdvisor,
    UntrustedExternalInputValidator,
    verify_hybrid_architecture_integrity,
)
from nova.hybrid_cloud.gateway_and_fusion import (
    SPECIALIST_ROLES,
    SpecialistFusionCoordinator,
    UnifiedCloudFrontierGateway,
)
from nova.hybrid_cloud.persistence_and_resources import (
    CloudAndLocalResourceIntelligence,
    OfflineCloudQueueManager,
    UnifiedAutonomousSubtaskCoordinator,
)
from nova.hybrid_cloud.privacy_gateway import (
    CloudPrivacyGateway,
    KaliLocalCloudDiagnosticCoordinator,
)
from nova.intelligence import IntelligenceOrchestrator, ModelManager
from nova.observability import Redactor
from nova.resources import ResourceManager
from nova.tools.registry import ToolDefinition, ToolOutcome, ToolRegistry


class HybridCloudIntelligenceService:
    """§1–§11 Coordinator uniting Local Kali OS Hosting with Cloud Frontier Intelligence.

    Constructed without filesystem `mkdir()` or unguarded SQLite queries in `__init__`
    so `create_app()` import-time initialization remains completely side-effect-free.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        db: Database,
        model_manager: ModelManager,
        orchestrator: IntelligenceOrchestrator,
        tool_registry: ToolRegistry,
        autonomy_policy: Any,
        resource_monitor: ResourceManager,
        redactor: Redactor,
        knowledge_store: Any | None = None,
        offline_coordinator: Any | None = None,
        app_root: Path | None = None,
    ) -> None:
        self.settings = settings
        self.db = db
        self.model_manager = model_manager
        self.orchestrator = orchestrator
        self.tool_registry = tool_registry
        self.autonomy_policy = autonomy_policy
        self.resource_monitor = resource_monitor
        self.redactor = redactor
        self.app_root = app_root or Path(__file__).resolve().parents[2]

        self.validator = UntrustedExternalInputValidator()
        self.llama_cpp_advisor = LlamaCppFallbackAdvisor()
        self.privacy_gateway = CloudPrivacyGateway(db=db, redactor=redactor)
        self.gateway = UnifiedCloudFrontierGateway(
            settings=settings,
            db=db,
            model_manager=model_manager,
            orchestrator=orchestrator,
            privacy_gateway=self.privacy_gateway,
            validator=self.validator,
        )
        self.fusion = SpecialistFusionCoordinator(
            gateway=self.gateway,
            tool_registry=tool_registry,
            knowledge_store=knowledge_store,
        )
        self.kali_separator = KaliLocalCloudDiagnosticCoordinator(
            db=db,
            privacy_gateway=self.privacy_gateway,
            tool_registry=tool_registry,
            autonomy_policy=autonomy_policy,
            validator=self.validator,
        )
        self.offline_queue = OfflineCloudQueueManager(
            db=db,
            gateway=self.gateway,
            offline_coordinator=offline_coordinator,
        )
        self.resource_intel = CloudAndLocalResourceIntelligence(
            settings=settings,
            db=db,
            resource_monitor=resource_monitor,
            gateway=self.gateway,
            queue_manager=self.offline_queue,
        )
        self.subtask_coordinator = UnifiedAutonomousSubtaskCoordinator(
            db=db,
            tool_registry=tool_registry,
            autonomy_policy=autonomy_policy,
            resource_intelligence=self.resource_intel,
            queue_manager=self.offline_queue,
            workspace_dir=settings.workspace_dir,
        )

    def bind_runtime_orchestrator(self, model_manager: ModelManager, orchestrator: IntelligenceOrchestrator) -> None:
        """Bind to the active ModelManager & IntelligenceOrchestrator so no competing registry exists (§8)."""
        self.model_manager = model_manager
        self.orchestrator = orchestrator
        self.gateway.model_manager = model_manager
        self.gateway.orchestrator = orchestrator

    def status_summary(self) -> dict[str, Any]:
        """Full §1–§11 status snapshot for `/api/health`, `/api/gateway/status`, CLI & Native Qt UI."""
        arch = verify_hybrid_architecture_integrity(self.app_root)
        lifecycle = self.gateway.model_lifecycle_inventory()
        telemetry = self.resource_intel.snapshot_separated_telemetry()
        llama_info = self.llama_cpp_advisor.inspect_runtime(
            available_ram_mb=int(telemetry["local_host_resources"]["memory_available_mb"] or 4096)
        )
        queued = self.db.list_offline_cloud_tasks(status="queued_waiting_cloud", limit=50)
        transmissions = self.db.list_cloud_transmissions(limit=25)
        local_projects = self.db.list_local_only_projects()
        provider_policies = self.db.list_provider_privacy_policies()
        return {
            "master_architecture": "locally_hosted_os_with_cloud_frontier_intelligence",
            "sections": "1-11",
            "architecture_verification": arch,
            "invariants": dict(HYBRID_INVARIANTS),
            "specialist_roles": list(SPECIALIST_ROLES),
            "model_lifecycle": {
                "provider_count": lifecycle["provider_count"],
                "profile_count": lifecycle["profile_count"],
                "counts": lifecycle["lifecycle_counts"],
                "buckets": lifecycle["lifecycle_buckets"],
                "hardcoded_model_ids": lifecycle["hardcoded_model_ids"],
            },
            "privacy_gateway": {
                "recent_transmissions_count": len(transmissions),
                "recent_transmissions": transmissions,
                "local_only_projects": local_projects,
                "provider_policies": provider_policies,
                "silent_larger_payload_fallback_allowed": False,
            },
            "offline_cloud_queue": {
                "cloud_online": self.offline_queue.is_cloud_online(),
                "queued_waiting_cloud_count": len(queued),
                "queued_items": queued[:15],
                "false_cloud_completion_when_offline": False,
            },
            "llama_cpp_fallback": llama_info,
            "separated_resources": telemetry,
        }


class _EmptyArgs(BaseModel):
    pass


class _TransmissionsArgs(BaseModel):
    provider_type: str = Field(default="", max_length=64)
    limit: int = Field(default=20, ge=1, le=100)


class _LlamaCheckArgs(BaseModel):
    model_id: str = Field(min_length=1, max_length=200)
    available_ram_mb: int | None = Field(default=None, ge=256, le=1_048_576)


def register_hybrid_cloud_tools(registry: ToolRegistry, service: HybridCloudIntelligenceService) -> None:
    """Register read-only local diagnostic & transparency tools inside NOVA's single ToolRegistry."""

    async def _arch_status(_args: BaseModel, _approved: bool) -> ToolOutcome:
        snap = service.status_summary()
        return ToolOutcome(
            status="completed",
            summary="Collected hybrid local-OS + cloud-frontier architecture & lifecycle status.",
            data={
                "architecture": snap["master_architecture"],
                "model_lifecycle_counts": snap["model_lifecycle"]["counts"],
                "queued_cloud_tasks": snap["offline_cloud_queue"]["queued_waiting_cloud_count"],
                "invariants": snap["invariants"],
            },
        )

    async def _transmissions(args: BaseModel, _approved: bool) -> ToolOutcome:
        parsed: _TransmissionsArgs = args  # type: ignore[assignment]
        rows = service.db.list_cloud_transmissions(provider_type=parsed.provider_type, limit=parsed.limit)
        return ToolOutcome(
            status="completed",
            summary=f"Retrieved {len(rows)} secret-free cloud transmission audit entry(ies).",
            data={"transmissions": rows},
        )

    async def _llama_check(args: BaseModel, _approved: bool) -> ToolOutcome:
        parsed: _LlamaCheckArgs = args  # type: ignore[assignment]
        fit = service.llama_cpp_advisor.evaluate_candidate(parsed.model_id, parsed.available_ram_mb)
        return ToolOutcome(
            status="completed",
            summary=fit["reason"],
            data=fit,
        )

    async def _resource_intel(_args: BaseModel, _approved: bool) -> ToolOutcome:
        tel = service.resource_intel.snapshot_separated_telemetry()
        return ToolOutcome(
            status="completed",
            summary="Sampled separated local host resources and external cloud API usage.",
            data=tel,
        )

    for tool_def in (
        ToolDefinition(
            name="gateway.architecture_status",
            description="Inspect hybrid local-OS vs cloud-frontier architecture invariants, 5-state model lifecycle, and offline cloud queue.",
            parameters={"type": "object", "properties": {}, "additionalProperties": False},
            input_model=_EmptyArgs,
            handler=_arch_status,
            permission="diagnostics",
            category="gateway",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="gateway.cloud_transmissions",
            description="List secret-free cloud privacy gateway audit records showing provider recipients and included files/categories.",
            parameters={
                "type": "object",
                "properties": {
                    "provider_type": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                },
                "additionalProperties": False,
            },
            input_model=_TransmissionsArgs,
            handler=_transmissions,
            permission="diagnostics",
            category="gateway",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="gateway.llama_cpp_check",
            description="Check whether a candidate GGUF model is compact, quantized, and fits available host RAM for optional offline llama.cpp fallback.",
            parameters={
                "type": "object",
                "properties": {
                    "model_id": {"type": "string"},
                    "available_ram_mb": {"type": "integer"},
                },
                "required": ["model_id"],
                "additionalProperties": False,
            },
            input_model=_LlamaCheckArgs,
            handler=_llama_check,
            permission="diagnostics",
            category="gateway",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="gateway.resource_intelligence",
            description="Inspect local CPU/RAM/storage/network headroom separately from external cloud API requests, latency, and cost estimates.",
            parameters={"type": "object", "properties": {}, "additionalProperties": False},
            input_model=_EmptyArgs,
            handler=_resource_intel,
            permission="diagnostics",
            category="gateway",
            autonomy_class="routine",
        ),
    ):
        if registry.get(tool_def.name) is None:
            registry.register(tool_def)
