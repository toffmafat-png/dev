"""§149–§160 Unified ToolRegistry Definitions for System Access, Hardware
Intelligence, Screen Recording, Observability, Infrastructure Knowledge, and
Authorized Remote Server Administration.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from nova.system_access.service import SystemAccessService
from nova.tools.registry import ToolDefinition, ToolOutcome


class HardwareExploreInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(default="", max_length=200)
    device_type: str = Field(default="", max_length=64)
    status_category: str = Field(default="", max_length=64)
    refresh: bool = True


class DriverDiagnoseInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: str = Field(default="", max_length=120)
    diagnostic_evidence: dict[str, Any] = Field(default_factory=dict)


class DeviceOperationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: str = Field(min_length=1, max_length=120)
    operation: str = Field(default="inspect_status", max_length=64)
    params: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = True


class ScreenshotCaptureInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capture_mode: str = Field(default="full_screen", max_length=40)
    region: str = Field(default="", max_length=64)
    task_id: str = Field(default="", max_length=80)


class EmptyHealthInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class InfraKnowledgeSearchInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    category: str = Field(default="", max_length=64)
    query: str = Field(default="", max_length=200)


class RemoteServerAuditInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    aliases: list[str] = Field(default_factory=list)


def build_system_access_tools(service_provider: Callable[[], SystemAccessService]) -> list[ToolDefinition]:
    """Build `ToolDefinition` instances registered into NOVA X's unified `ToolRegistry`."""

    async def _hw_explore(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = HardwareExploreInput.model_validate(args.model_dump())
        res = service_provider().hardware.search(
            p.query,
            device_type=p.device_type,
            status_category=p.status_category,
            refresh=p.refresh,
        )
        return ToolOutcome(status="success", summary=f"Matched {res['match_count']} hardware device(s).", data=res)

    async def _driver_diagnose(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = DriverDiagnoseInput.model_validate(args.model_dump())
        res = service_provider().drivers.diagnose(
            device_id=p.device_id,
            diagnostic_evidence=p.diagnostic_evidence or None,
        )
        return ToolOutcome(
            status="success",
            summary=f"Diagnosed {len(res['findings'])} finding(s); {len(res['candidate_repairs'])} candidate repair(s).",
            data=res,
        )

    async def _device_op(args: BaseModel, approved: bool) -> ToolOutcome:
        p = DeviceOperationInput.model_validate(args.model_dump())
        if not p.dry_run and p.operation not in {"inspect_status", "read_sensors", "interface_stats", "check_connectivity", "diagnostic_test"} and not approved:
            return ToolOutcome(
                status="approval_required",
                summary=f"Device operation '{p.operation}' on '{p.device_id}' requires operator approval.",
                approval_payload={"device_id": p.device_id, "operation": p.operation, "params": p.params},
            )
        res = service_provider().device_ops.execute_operation(
            p.device_id,
            p.operation,
            params=p.params,
            dry_run=p.dry_run,
            operator_approved=approved,
        )
        return ToolOutcome(status="success" if res.get("ok") else "error", summary=str(res.get("status") or "done"), data=res)

    async def _screen_shot(args: BaseModel, approved: bool) -> ToolOutcome:
        p = ScreenshotCaptureInput.model_validate(args.model_dump())
        if not approved:
            return ToolOutcome(
                status="approval_required",
                summary=f"Screenshot capture ({p.capture_mode}) requires explicit session approval.",
                approval_payload={"capture_mode": p.capture_mode, "region": p.region},
            )
        res = service_provider().recording_studio.capture_screenshot(
            capture_mode=p.capture_mode,
            region=p.region,
            task_id=p.task_id,
        )
        return ToolOutcome(status="success", summary=f"Captured screenshot ({res['size_bytes']} bytes).", data=res)

    async def _health_snap(_args: BaseModel, _approved: bool) -> ToolOutcome:
        svc = service_provider()
        snap = svc.monitor.collect_snapshot()
        alerts = svc.monitor.evaluate_alerts(snap)
        return ToolOutcome(
            status="success",
            summary=f"System health collected in {snap['collection_overhead_ms']} ms ({alerts['triggered_count']} alert(s)).",
            data={"snapshot": snap, "alerts": alerts},
        )

    async def _infra_search(args: BaseModel, _approved: bool) -> ToolOutcome:
        p = InfraKnowledgeSearchInput.model_validate(args.model_dump())
        recs = service_provider().infra_knowledge.list_records(category=p.category, query=p.query)
        return ToolOutcome(status="success", summary=f"Found {len(recs)} infrastructure knowledge record(s).", data={"count": len(recs), "records": recs})

    async def _server_audit(args: BaseModel, approved: bool) -> ToolOutcome:
        p = RemoteServerAuditInput.model_validate(args.model_dump())
        if not approved:
            return ToolOutcome(
                status="approval_required",
                summary="Auditing remote SSH servers requires explicit operator approval.",
                approval_payload={"aliases": p.aliases},
            )
        res = service_provider().servers.multi_server_audit(p.aliases or None)
        return ToolOutcome(
            status="success",
            summary=f"Audited {res['server_count']} server(s); {res['healthy_count']} healthy.",
            data=res,
        )

    return [
        ToolDefinition(
            name="hardware.explore",
            description="Search discovered Linux hardware, drivers, permissions, and device status (§149).",
            parameters=HardwareExploreInput.model_json_schema(),
            input_model=HardwareExploreInput,
            handler=_hw_explore,
            permission="system_inspect",
            category="hardware",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="hardware.diagnose_drivers",
            description="Run evidence-based Linux driver, kernel module, and firmware diagnostics (§150).",
            parameters=DriverDiagnoseInput.model_json_schema(),
            input_model=DriverDiagnoseInput,
            handler=_driver_diagnose,
            permission="system_inspect",
            category="hardware",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="hardware.device_operation",
            description="Inspect or preview supported device/interface operations with safety checks (§151).",
            parameters=DeviceOperationInput.model_json_schema(),
            input_model=DeviceOperationInput,
            handler=_device_op,
            permission="device_control",
            category="hardware",
            autonomy_class="approval_required",
        ),
        ToolDefinition(
            name="screen.capture_screenshot",
            description="Capture a session-aware screenshot (full screen, window, or selected region) (§155).",
            parameters=ScreenshotCaptureInput.model_json_schema(),
            input_model=ScreenshotCaptureInput,
            handler=_screen_shot,
            permission="desktop_capture",
            category="recording",
            autonomy_class="approval_required",
        ),
        ToolDefinition(
            name="observability.health_snapshot",
            description="Collect low-overhead CPU, RAM, swap, disk, thermal, service, and network telemetry (§156).",
            parameters=EmptyHealthInput.model_json_schema(),
            input_model=EmptyHealthInput,
            handler=_health_snap,
            permission="system_inspect",
            category="observability",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="infrastructure.knowledge_search",
            description="Query structured infrastructure and environment knowledge with TTL staleness flags (§159).",
            parameters=InfraKnowledgeSearchInput.model_json_schema(),
            input_model=InfraKnowledgeSearchInput,
            handler=_infra_search,
            permission="memory_read",
            category="infrastructure",
            autonomy_class="routine",
        ),
        ToolDefinition(
            name="remote.audit_servers",
            description="Run read-only OpenSSH health checks across registered authorized servers (§157).",
            parameters=RemoteServerAuditInput.model_json_schema(),
            input_model=RemoteServerAuditInput,
            handler=_server_audit,
            permission="remote_ssh",
            category="remote",
            autonomy_class="approval_required",
        ),
    ]
