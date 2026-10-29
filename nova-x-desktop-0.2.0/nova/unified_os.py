"""§3, §5, §16, §20 & §23 Unified Operating System Coordinator & Durable Worker.

Unites NOVA X's single intelligence core, single task engine, single capability
registry, single shared memory system, single permission framework, single event
bus, and single creation/verification pipeline without duplicating state.
"""
from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from nova.cognition.service import CognitionService
    from nova.db import Database
    from nova.intelligence import ModelManager
    from nova.platform_service import PlatformService

PIPELINE_STAGES: tuple[str, ...] = (
    "understand",
    "discover",
    "plan",
    "prepare",
    "produce",
    "integrate",
    "verify",
    "repair",
    "package",
    "record",
    "report",
)


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


class BackgroundWorkerSupervisor:
    """§16 & §20 Tracks and runs durable user-level background job ticks honestly."""

    def __init__(self, db: Database, max_scheduled_runs_per_day: int = 5) -> None:
        self.db = db
        self.max_scheduled_runs_per_day = max(0, int(max_scheduled_runs_per_day))

    def status(self, stale_after_seconds: float = 90.0) -> dict[str, Any]:
        rows = self.db.list_worker_heartbeats()
        now = datetime.now(UTC)
        active_workers: list[dict[str, Any]] = []
        for row in rows:
            pid = int(row.get("pid") or 0)
            alive = _pid_alive(pid) and row.get("status") == "running"
            fresh = False
            try:
                updated = datetime.fromisoformat(str(row["updated_at"]))
                fresh = (now - updated).total_seconds() <= stale_after_seconds
            except ValueError:
                fresh = False
            if alive and fresh:
                active_workers.append(row)
        running = len(active_workers) > 0
        return {
            "running": running,
            "status": "running" if running else "not_running",
            "active_workers": active_workers,
            "recorded_workers": rows[:5],
            "honesty_note": (
                "Background worker is active for this user session."
                if running
                else "Background worker is NOT running; scheduled workflows pause until `nova-x worker` or the desktop scheduler runs, and never run while powered off (§16)."
            ),
        }

    def tick_once(self, worker_id: str = "cli-user-worker") -> dict[str, Any]:
        pid = os.getpid()
        due = self.db.dispatch_due_goals(self.max_scheduled_runs_per_day) if self.max_scheduled_runs_per_day > 0 else []
        hb = self.db.upsert_worker_heartbeat(
            worker_id,
            pid=pid,
            mode="user_worker",
            status="running",
            dispatched_count=len(due),
            detail=f"Checked scheduled goals; dispatched {len(due)} task(s).",
        )
        return {"worker": hb, "dispatched_tasks": due}

    def mark_stopped(self, worker_id: str = "cli-user-worker") -> dict[str, Any]:
        return self.db.upsert_worker_heartbeat(
            worker_id,
            pid=os.getpid(),
            mode="user_worker",
            status="stopped",
            detail="Worker exited cleanly.",
        )


class UnifiedOperatingKernel:
    """§3, §5 & §23 Single 11-stage Autonomous Creation & Verification Pipeline."""

    def __init__(
        self,
        *,
        db: Database,
        platform: PlatformService,
        cognition: CognitionService | None = None,
        model_manager: ModelManager | None = None,
    ) -> None:
        self.db = db
        self.platform = platform
        self.cognition = cognition
        self.model_manager = model_manager
        self.worker = BackgroundWorkerSupervisor(db)

    def architecture_manifest(self) -> dict[str, Any]:
        """§3 Return live status of all 12 cooperating OS modules (A–L) with zero duplicate engines."""
        profiles = self.model_manager.list_profiles() if self.model_manager else []
        worker_state = self.worker.status()
        res_budget = self.platform.resources.assess()
        return {
            "defining_principle": "one interface, one coordinated intelligence system, one shared task engine, one permission framework, and a flexible ecosystem of real capabilities",
            "agi_or_consciousness_claimed": False,
            "root_required": False,
            "running_as_root": (os.geteuid() == 0) if hasattr(os, "geteuid") else False,
            "operating_modes": ["fast", "balanced", "frontier_fusion", "maximum_intelligence"],
            "autonomy_modes": ["assisted", "routine", "advanced", "high"],
            "pipeline_stages": list(PIPELINE_STAGES),
            "modules": {
                "A_native_desktop_shell": {"module": "nova.desktop.app", "primary_ui": "PySide6/Qt native Kali Linux window"},
                "B_intelligence_core": {"module": "nova.intelligence + nova.cognition", "configured_profiles": sum(1 for p in profiles if p.get("configured"))},
                "C_autonomous_task_engine": {"module": "nova.engine.TaskEngine", "active_tasks": sum(1 for t in self.db.list_tasks(limit=50) if t.get("state") in {"queued", "running", "waiting_approval"})},
                "D_universal_capability_registry": {"module": "nova.capabilities + nova.creation.registry", "registered_tools": len(self.platform.tools.all_tools())},
                "E_local_execution_engine": {"module": "nova.desktop.commands + nova.terminal + nova.desktop_control", "desktop_session": self.platform.desktop_control.inspect_session().display_server},
                "F_ai_provider_gateway": {"module": "nova.model_providers", "supported_providers": len(self.model_manager.provider_catalog()) if self.model_manager else 8},
                "G_memory_and_knowledge_engine": {"module": "nova.memory_hub + nova.knowledge", "memory_enabled": self.platform.memory.is_enabled(), "fts5": self.platform.knowledge.fts_available},
                "H_universal_creation_engine": {"module": "nova.creation.engine", "projects": self.db.creation_stats().get("creation_projects", 0)},
                "I_automation_and_integration_engine": {"module": "nova.workflows + nova.plugins + nova.mcp_client", "worker_status": worker_state["status"]},
                "J_verification_and_improvement_engine": {"module": "nova.creation.qa + nova.self_improvement", "experiments": len(self.db.list_improvement_experiments(limit=20))},
                "K_security_and_policy_engine": {"module": "nova.autonomy + nova.desktop.policy + nova.sandbox", "autonomy_level": self.platform.autonomy_policy.get()["level"]},
                "L_observability_and_reliability_engine": {"module": "nova.observability + nova.governance + nova.resources", "resource_pressure": res_budget.pressure},
            },
        }

    async def execute_unified_pipeline(
        self,
        request_text: str,
        *,
        domain_override: str = "",
        package: bool = True,
    ) -> dict[str, Any]:
        """§5 & §23 Execute Understand -> Discover -> Plan -> Prepare -> Produce -> Integrate -> Verify -> Repair -> Package -> Record -> Report."""
        correlation_id = f"uos-{uuid.uuid4().hex[:12]}"
        stage_log: list[dict[str, Any]] = []

        def _mark(stage: str, status: str, detail: dict[str, Any]) -> None:
            stage_log.append({"stage": stage, "status": status, "timestamp": _iso(), "detail": detail})

        # 1. Understand + Memory context resolution (§5.1–5.2)
        intent = self.platform.creation.recognize_intent(request_text)
        mem_ctx = self.platform.memory.retrieve_relevant_context(request_text, max_chars=800)
        _mark("understand", "completed", {"domain": intent["domain"], "artifact_type": intent["artifact_type"], "memory_hits": len(mem_ctx["snippets"])})

        # 2. Discover capabilities & feasibility (§5.3–5.4)
        self.platform.creation.discovery.discover()
        target_domain = domain_override.strip() or intent["domain"]
        toolchain = self.platform.creation.toolchains.select_toolchain(target_domain, preferred_language=intent["preferred_language"])
        selected_ids = [t["id"] for t in toolchain.get("selected_tools", [])]
        _mark("discover", "completed", {"feasible_locally": bool(selected_ids), "selected_tools": selected_ids})

        # 3. Plan & Acceptance Criteria (§5.5–5.6)
        preflight: dict[str, Any] = {}
        if self.cognition is not None:
            preflight = self.cognition.review_plan(
                correlation_id,
                request_text,
                intent["milestones"],
                tools=self.platform.tools,
            )
        _mark("plan", "completed", {"milestones": intent["milestones"], "cognition_preflight_ready": bool(preflight)})

        # 4–9. Prepare, Produce, Integrate, Verify, Repair & Package via UniversalCreationEngine
        await self.platform.safe_emit_event(
            "os.pipeline.started",
            "unified_os",
            task_id=correlation_id,
            payload={"domain": target_domain},
        )
        created = await self.platform.creation.create_from_intent(
            request_text,
            domain_override=target_domain,
            package=package,
            run_refinement=True,
        )
        _mark("prepare", "completed", {"project_id": created["project_id"], "project_dir": created["project_dir"]})
        _mark("produce", "completed", {"primary_artifacts": created["primary_artifacts"]})
        _mark("integrate", "completed", created["integration"])
        _mark("verify", "completed" if created["qa"]["passed"] else "attention", {"quality_score": created["qa"]["quality_score"], "passed": created["qa"]["passed"]})
        _mark("repair", "completed", {"final_version": created["version"]})
        _mark("package", "completed" if created["package"].get("packaged") else "skipped", created["package"])

        # 10. Record into SharedMemorySystem + TraceCollector + EventBus
        if self.platform.memory.is_enabled():
            self.platform.memory.store(
                category="project_context",
                subject=f"{created['name']} ({created['domain']})",
                content=f"Objective: {request_text[:240]} | QA passed={created['qa']['passed']} | Dir: {created['project_dir']}",
                provenance="verified_test_result" if created["qa"]["passed"] else "tool_observation",
                source_ref=created["project_id"],
                project_id=created["project_id"],
                evidence_verified=bool(created["qa"]["passed"]),
            )
        self.platform.safe_record_span(
            operation="os.unified_pipeline",
            category="unified_os",
            status="ok" if created["qa"]["passed"] else "error",
            task_id=correlation_id,
            summary=f"Unified pipeline completed for {created['name']}",
            attributes={"domain": created["domain"], "project_id": created["project_id"]},
        )
        _mark("record", "completed", {"correlation_id": correlation_id})

        # 11. Report completion & unresolved blockers
        unresolved = list(created.get("limitations") or [])
        _mark("report", "completed", {"unresolved_count": len(unresolved)})
        await self.platform.safe_emit_event(
            "os.pipeline.completed",
            "unified_os",
            task_id=correlation_id,
            payload={"project_id": created["project_id"], "passed": created["qa"]["passed"]},
        )
        return {
            "correlation_id": correlation_id,
            "stages": stage_log,
            "deliverable": created,
            "memory_context_used": mem_ctx["snippets"],
            "unresolved_blockers_or_limitations": unresolved,
        }
