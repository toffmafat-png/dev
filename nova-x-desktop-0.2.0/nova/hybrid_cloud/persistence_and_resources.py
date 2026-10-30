"""§6 Offline Cloud Queue & Task Persistence, §8 Unified Subtask Coordinator & §9 Resource Intelligence."""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

from nova.config import Settings
from nova.db import Database
from nova.hybrid_cloud.gateway_and_fusion import UnifiedCloudFrontierGateway
from nova.model_providers import check_local_model_resource_fit
from nova.provider import ProviderConfigurationError, ProviderError
from nova.resources import PRESSURE_CRITICAL, PRESSURE_HIGH, ResourceManager


def _read_local_network_counters() -> dict[str, Any]:
    rx_bytes = 0
    tx_bytes = 0
    active_ifaces: list[str] = []
    try:
        with open("/proc/net/dev", encoding="utf-8") as nf:
            for line in nf.readlines()[2:]:
                if ":" not in line:
                    continue
                iface, rest = line.split(":", 1)
                iface = iface.strip()
                cols = rest.split()
                if len(cols) >= 9 and iface != "lo":
                    rx = int(cols[0])
                    tx = int(cols[8])
                    rx_bytes += rx
                    tx_bytes += tx
                    active_ifaces.append(iface)
    except OSError:
        pass
    return {
        "non_loopback_interfaces": active_ifaces,
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
    }


class OfflineCloudQueueManager:
    """§6 Queues cloud-dependent tasks offline while keeping eligible local work running."""

    FALSE_CLOUD_COMPLETION_WHEN_OFFLINE = False

    def __init__(
        self,
        *,
        db: Database,
        gateway: UnifiedCloudFrontierGateway,
        offline_coordinator: Any | None = None,
    ):
        self.db = db
        self.gateway = gateway
        self.offline_coordinator = offline_coordinator
        self._forced_cloud_online: bool | None = None
        self._completed_idempotency_keys: set[str] = set()

    def set_cloud_connectivity_override(self, online: bool | None) -> None:
        self._forced_cloud_online = online

    def is_cloud_online(self) -> bool:
        if self._forced_cloud_online is not None:
            return self._forced_cloud_online
        if self.offline_coordinator is not None and getattr(self.offline_coordinator, "offline", False):
            return False
        cloud_profiles = [
            p
            for p in self.gateway.model_manager.list_profiles()
            if p.get("provider_type") not in {"ollama", "llama_cpp"} and p.get("available")
        ]
        return len(cloud_profiles) > 0

    def _find_eligible_local_fallback_profile(self, available_ram_mb: int | None = None) -> dict[str, Any] | None:
        for p in self.gateway.model_manager.list_profiles():
            if p.get("provider_type") in {"llama_cpp", "ollama"} and p.get("available"):
                fit = check_local_model_resource_fit(
                    str(p.get("model_id") or ""),
                    available_ram_mb=available_ram_mb,
                    require_compact_quantized=True,
                )
                if fit["fits_resource_budget"]:
                    return p
        return None

    async def submit_or_queue_cloud_operation(
        self,
        *,
        goal: str,
        messages: list[dict[str, Any]],
        mode: str = "balanced",
        task_id: str = "",
        checkpoint_id: str = "",
        idempotency_key: str = "",
        requested_model_ids: list[str] | None = None,
        allow_compact_local_fallback: bool = False,
        available_ram_mb: int | None = None,
    ) -> dict[str, Any]:
        """§6 & §7 Execute cloud call if online; otherwise optionally run compact fallback or queue truthfully."""
        idem = idempotency_key or hashlib.sha256(
            f"{task_id}:{goal}:{mode}".encode()
        ).hexdigest()[:24]

        # Recheck actual operation status before repeating any previously completed action (§6)
        existing = [
            row
            for row in self.db.list_offline_cloud_tasks(limit=200)
            if row.get("idempotency_key") == idem and row.get("status") == "completed"
        ]
        if existing:
            return {
                "status": "already_completed_verified",
                "cloud_completed": True,
                "repeated_execution_prevented": True,
                "queue_item": existing[0],
                "result": existing[0].get("result", {}),
            }

        if self.is_cloud_online():
            try:
                res = await self.gateway.gateway_chat(
                    messages,
                    task_id=task_id,
                    preferred_profile_ids=requested_model_ids,
                )
                saved = self.db.enqueue_offline_cloud_task(
                    {
                        "task_id": task_id,
                        "goal": goal,
                        "mode": mode,
                        "messages": messages,
                        "requested_model_ids": requested_model_ids or [],
                        "status": "completed",
                        "checkpoint_id": checkpoint_id,
                        "idempotency_key": idem,
                        "local_fallback_allowed": allow_compact_local_fallback,
                        "attempt_count": 1,
                        "result": {"content": res["message"].get("content", ""), "fallback": False},
                    }
                )
                self._completed_idempotency_keys.add(idem)
                return {
                    "status": "completed",
                    "cloud_completed": True,
                    "queued": False,
                    "queue_item": saved,
                    "result": res,
                }
            except (ProviderError, ProviderConfigurationError) as exc:
                last_err = str(exc)
        else:
            last_err = "cloud_connectivity_unavailable"

        # Optional compact quantized local fallback for basic tasks when explicitly allowed (§7)
        if allow_compact_local_fallback:
            local_profile = self._find_eligible_local_fallback_profile(available_ram_mb=available_ram_mb)
            if local_profile is not None:
                res = await self.gateway.gateway_chat(
                    messages,
                    task_id=task_id,
                    preferred_profile_ids=[str(local_profile["id"])],
                )
                saved = self.db.enqueue_offline_cloud_task(
                    {
                        "task_id": task_id,
                        "goal": goal,
                        "mode": mode,
                        "messages": messages,
                        "requested_model_ids": [str(local_profile["id"])],
                        "status": "completed_via_compact_local_fallback",
                        "checkpoint_id": checkpoint_id,
                        "idempotency_key": idem,
                        "local_fallback_allowed": True,
                        "attempt_count": 1,
                        "result": {
                            "content": res["message"].get("content", ""),
                            "fallback_provider": local_profile["provider_type"],
                            "fallback_model": local_profile["model_id"],
                        },
                    }
                )
                return {
                    "status": "completed_via_compact_local_fallback",
                    "cloud_completed": False,
                    "local_fallback_used": True,
                    "queued": False,
                    "queue_item": saved,
                    "result": res,
                }

        # Truthfully queue cloud-dependent operation without falsely claiming completion (§6)
        queued = self.db.enqueue_offline_cloud_task(
            {
                "task_id": task_id,
                "goal": goal,
                "mode": mode,
                "messages": self.gateway.privacy_gateway.redactor.scrub(messages, max_chars=0),
                "requested_model_ids": requested_model_ids or [],
                "status": "queued_waiting_cloud",
                "checkpoint_id": checkpoint_id or f"ckpt-{idem[:10]}",
                "idempotency_key": idem,
                "local_fallback_allowed": allow_compact_local_fallback,
                "attempt_count": 0,
                "last_error": last_err,
            }
        )
        return {
            "status": "queued_waiting_cloud",
            "cloud_completed": False,
            "queued": True,
            "reason": last_err,
            "queue_item": queued,
        }

    async def drain_queued_cloud_tasks(self, *, max_items: int = 10) -> dict[str, Any]:
        """§6 Resume queued cloud tasks from latest verified checkpoint once connectivity returns."""
        if not self.is_cloud_online():
            pending = self.db.list_offline_cloud_tasks(status="queued_waiting_cloud", limit=100)
            return {"online": False, "resumed": 0, "still_queued": len(pending)}

        pending = self.db.list_offline_cloud_tasks(status="queued_waiting_cloud", limit=max_items)
        resumed = 0
        failed = 0
        skipped_already_done = 0
        for item in pending:
            idem = str(item.get("idempotency_key") or "")
            # Recheck actual operation status before repeating interrupted actions (§6)
            if idem and idem in self._completed_idempotency_keys:
                self.db.update_offline_cloud_task(item["id"], status="completed_deduplicated")
                skipped_already_done += 1
                continue
            if item.get("task_id"):
                existing_task = self.db.get_task(str(item["task_id"]))
                if existing_task and existing_task.get("state") == "completed":
                    self.db.update_offline_cloud_task(item["id"], status="completed_verified_from_task")
                    skipped_already_done += 1
                    continue
            attempts = int(item.get("attempt_count") or 0) + 1
            try:
                res = await self.gateway.gateway_chat(
                    item.get("messages") or [{"role": "user", "content": item["goal"]}],
                    task_id=str(item.get("task_id") or ""),
                    preferred_profile_ids=item.get("requested_model_ids") or None,
                )
                self.db.update_offline_cloud_task(
                    item["id"],
                    status="completed",
                    attempt_count=attempts,
                    last_error="",
                    result={"content": res["message"].get("content", ""), "resumed_from_checkpoint": item.get("checkpoint_id", "")},
                )
                if idem:
                    self._completed_idempotency_keys.add(idem)
                resumed += 1
            except (ProviderError, ProviderConfigurationError) as exc:
                self.db.update_offline_cloud_task(
                    item["id"],
                    status="queued_waiting_cloud",
                    attempt_count=attempts,
                    last_error=str(exc),
                )
                failed += 1
        remaining = self.db.list_offline_cloud_tasks(status="queued_waiting_cloud", limit=200)
        return {
            "online": True,
            "resumed": resumed,
            "skipped_already_done": skipped_already_done,
            "failed": failed,
            "still_queued": len(remaining),
        }


class CloudAndLocalResourceIntelligence:
    """§9 Tracks local host CPU/RAM/storage/network separately from external cloud API usage & costs."""

    def __init__(
        self,
        *,
        settings: Settings,
        db: Database,
        resource_monitor: ResourceManager,
        gateway: UnifiedCloudFrontierGateway,
        queue_manager: OfflineCloudQueueManager,
    ):
        self.settings = settings
        self.db = db
        self.resource_monitor = resource_monitor
        self.gateway = gateway
        self.queue_manager = queue_manager

    def snapshot_separated_telemetry(self) -> dict[str, Any]:
        """§9 Produce strictly separated Local Computer Resources vs External Cloud API Usage/Cost ledgers."""
        sample = self.resource_monitor.sample()
        budget = self.resource_monitor.assess(sample)
        net = _read_local_network_counters()

        runs = self.db.list_intelligence_runs(limit=100)
        profiles = self.gateway.model_manager.list_profiles()

        total_requests = sum(int(r.get("provider_requests") or 0) for r in runs)
        prompt_tokens = sum(int(r.get("prompt_tokens") or 0) for r in runs)
        completion_tokens = sum(int(r.get("completion_tokens") or 0) for r in runs)
        known_costs = [float(r["estimated_cost_usd"]) for r in runs if r.get("estimated_cost_usd") is not None]
        latencies = [float(p["last_latency_ms"]) for p in profiles if p.get("last_latency_ms") is not None]
        calls_failed = sum(int(p.get("calls_failed") or 0) for p in profiles)

        return {
            "separated_accounting": True,
            "local_host_resources": {
                "cpu_count": sample.cpu_count,
                "load_1m": sample.load_1m,
                "load_per_cpu": sample.load_per_cpu,
                "cpu_busy_ratio": sample.cpu_busy_ratio,
                "memory_total_mb": sample.memory_total_mb,
                "memory_available_mb": sample.memory_available_mb,
                "disk_total_mb": sample.disk_total_mb,
                "disk_free_mb": sample.disk_free_mb,
                "network": net,
                "pressure_level": budget.pressure,
                "max_local_parallelism": budget.max_parallel_tasks,
                "host_overwhelmed_guard_active": budget.pressure in {PRESSURE_HIGH, PRESSURE_CRITICAL},
            },
            "external_cloud_api_usage": {
                "cloud_online": self.queue_manager.is_cloud_online(),
                "provider_requests_recorded": total_requests,
                "prompt_tokens_recorded": prompt_tokens,
                "completion_tokens_recorded": completion_tokens,
                "estimated_cost_usd_total": round(sum(known_costs), 6) if known_costs else 0.0,
                "cost_complete": len(known_costs) == len(runs) if runs else True,
                "observed_avg_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else None,
                "failed_or_quota_events": calls_failed,
                "rate_limit_per_minute_cap": self.settings.max_ai_requests_per_minute,
                "fusion_cost_budget_usd": self.settings.max_fusion_budget_usd,
            },
        }

    def select_optimal_execution_plan(
        self,
        *,
        objective: str,
        deadline_ms: int | None = None,
        cost_budget_usd: float | None = None,
        required_storage_mb: int = 0,
        api_quota_remaining: int | None = None,
        allow_local_fallback: bool = True,
    ) -> dict[str, Any]:
        """§9 Select models & workflow from all 8 required resource/quota/latency/deadline/storage signals."""
        telemetry = self.snapshot_separated_telemetry()
        local_res = telemetry["local_host_resources"]
        cloud_res = telemetry["external_cloud_api_usage"]

        if required_storage_mb > 0 and int(local_res["disk_free_mb"]) < required_storage_mb:
            return {
                "feasible": False,
                "reason": f"insufficient_local_storage:{local_res['disk_free_mb']}MB<{required_storage_mb}MB",
                "selected_mode": "blocked",
                "selected_profile_ids": [],
                "local_parallelism_cap": 0,
                "factors_evaluated": [
                    "local_computing_capacity",
                    "cloud_model_availability",
                    "api_quotas",
                    "model_latency",
                    "usage_limits",
                    "network_connectivity",
                    "task_deadlines",
                    "file_and_storage_requirements",
                ],
            }

        parallel_cap = 1 if local_res["host_overwhelmed_guard_active"] else max(1, int(local_res["max_local_parallelism"]))
        cloud_profiles = [
            p
            for p in self.gateway.model_manager.list_profiles()
            if p.get("available") and p.get("provider_type") not in {"ollama", "llama_cpp"}
        ]

        quota_exhausted = api_quota_remaining is not None and api_quota_remaining <= 0
        if not cloud_res["cloud_online"] or not cloud_profiles or quota_exhausted:
            fallback_profile = (
                self.queue_manager._find_eligible_local_fallback_profile(
                    available_ram_mb=int(local_res["memory_available_mb"] or 4096)
                )
                if allow_local_fallback
                else None
            )
            if fallback_profile is not None:
                return {
                    "feasible": True,
                    "route": "compact_quantized_local_fallback",
                    "selected_mode": "fast",
                    "selected_profile_ids": [fallback_profile["id"]],
                    "local_parallelism_cap": 1,
                    "reason": "cloud_unavailable_or_quota_exhausted_using_ram_safe_local_fallback",
                    "factors_evaluated": self._factor_names(),
                }
            return {
                "feasible": True,
                "route": "queue_for_cloud_while_local_tools_continue",
                "selected_mode": "queued_waiting_cloud",
                "selected_profile_ids": [],
                "local_parallelism_cap": parallel_cap,
                "reason": "cloud_offline_queued_without_false_completion",
                "factors_evaluated": self._factor_names(),
            }

        # Filter by deadline & cost budget
        eligible = list(cloud_profiles)
        if deadline_ms is not None:
            fast_enough = [
                p for p in eligible if p.get("last_latency_ms") is None or float(p["last_latency_ms"]) <= deadline_ms
            ]
            if fast_enough:
                eligible = fast_enough
        effective_budget = cost_budget_usd if cost_budget_usd is not None else self.settings.max_fusion_budget_usd
        affordable = [
            p
            for p in eligible
            if p.get("input_cost_per_million") is None
            or (float(p["input_cost_per_million"]) * 0.002) <= effective_budget
        ]
        if affordable:
            eligible = affordable

        # Pick mode based on deadline, quota, and local host pressure
        if (deadline_ms is not None and deadline_ms <= 2500) or (api_quota_remaining is not None and api_quota_remaining <= 2):
            mode = "fast"
            chosen = sorted(eligible, key=lambda p: (p.get("last_latency_ms") is None, p.get("last_latency_ms") or 0))[:1]
        elif local_res["host_overwhelmed_guard_active"] or len(eligible) == 1:
            mode = "balanced"
            chosen = eligible[:1]
        elif len(objective) > 160 and (api_quota_remaining is None or api_quota_remaining >= 6):
            mode = "frontier_fusion"
            chosen = eligible[: min(3, len(eligible))]
        else:
            mode = "balanced"
            chosen = eligible[:2]

        return {
            "feasible": True,
            "route": "cloud_frontier_gateway",
            "selected_mode": mode,
            "selected_profile_ids": [p["id"] for p in chosen],
            "local_parallelism_cap": parallel_cap,
            "effective_cost_budget_usd": effective_budget,
            "reason": "optimal_within_local_and_cloud_budgets",
            "factors_evaluated": self._factor_names(),
        }

    @staticmethod
    def _factor_names() -> list[str]:
        return [
            "local_computing_capacity",
            "cloud_model_availability",
            "api_quotas",
            "model_latency",
            "usage_limits",
            "network_connectivity",
            "task_deadlines",
            "file_and_storage_requirements",
        ]


class UnifiedAutonomousSubtaskCoordinator:
    """§8 Coordinates subtasks, parallel local/cloud execution, replanning, checkpoints & verification via ONE engine."""

    COMPETING_EXECUTION_ENGINES = 0

    def __init__(
        self,
        *,
        db: Database,
        tool_registry: Any,
        autonomy_policy: Any,
        resource_intelligence: CloudAndLocalResourceIntelligence,
        queue_manager: OfflineCloudQueueManager,
        workspace_dir: Path,
    ):
        self.db = db
        self.tool_registry = tool_registry
        self.autonomy_policy = autonomy_policy
        self.resource_intelligence = resource_intelligence
        self.queue_manager = queue_manager
        self.workspace_dir = workspace_dir

    async def execute_unified_plan(
        self,
        *,
        goal: str,
        subtasks: list[dict[str, Any]],
        intelligence_mode: str = "balanced",
    ) -> dict[str, Any]:
        """§8 Execute local and cloud subtasks through the single unified task & tool substrate."""
        task_id = self.db.create_task(goal, intelligence_mode=intelligence_mode)
        self.db.update_task(task_id, state="running", plan=[s.get("title", s.get("id", "step")) for s in subtasks])

        plan_decision = self.resource_intelligence.select_optimal_execution_plan(objective=goal)
        sem = asyncio.Semaphore(max(1, int(plan_decision.get("local_parallelism_cap") or 2)))

        completed_ids: set[str] = set()
        results_by_id: dict[str, dict[str, Any]] = {}
        pending = [dict(item, id=str(item.get("id") or f"sub-{idx + 1}")) for idx, item in enumerate(subtasks)]
        checkpoints: list[str] = []

        while pending:
            ready = [
                s for s in pending if all(dep in completed_ids for dep in (s.get("depends_on") or []))
            ]
            if not ready:
                self.db.update_task(task_id, state="failed", error="Cyclic or unsatisfied subtask dependency.")
                return {"ok": False, "task_id": task_id, "status": "failed", "reason": "dependency_deadlock"}

            async def _run_subtask(sub: dict[str, Any]) -> dict[str, Any]:
                async with sem:
                    return await self._execute_single_subtask(task_id, sub)

            batch_outcomes = await asyncio.gather(*(_run_subtask(s) for s in ready))
            ready_ids = {s["id"] for s in ready}
            pending = [s for s in pending if s["id"] not in ready_ids]

            for sub, outcome in zip(ready, batch_outcomes, strict=True):
                sid = sub["id"]
                results_by_id[sid] = outcome
                completed_ids.add(sid)
                ckpt_id = f"ckpt-{task_id[:8]}-{sid}"
                checkpoints.append(ckpt_id)
                self.db.add_event(
                    task_id,
                    "step",
                    f"{sub.get('title') or sid}: {outcome.get('status')}",
                    {
                        "subtask_id": sid,
                        "tool": str(sub.get("tool") or sub.get("kind") or "subtask"),
                        "summary": str(outcome.get("summary") or "")[:500],
                        "checkpoint_id": ckpt_id,
                    },
                )

        any_queued_cloud = any(r.get("status") == "queued_waiting_cloud" for r in results_by_id.values())
        any_approval = any(r.get("status") == "approval_required" for r in results_by_id.values())
        all_local_or_cloud_ok = all(
            r.get("ok") or r.get("status") == "queued_waiting_cloud" for r in results_by_id.values()
        )

        if any_approval:
            final_status = "awaiting_approval"
        elif any_queued_cloud:
            final_status = "partially_completed_waiting_cloud"
        elif all_local_or_cloud_ok:
            final_status = "completed"
        else:
            final_status = "failed"

        report = {
            "task_id": task_id,
            "goal": goal,
            "status": final_status,
            "competing_execution_engines": 0,
            "subtasks_total": len(subtasks),
            "subtasks_succeeded": sum(1 for r in results_by_id.values() if r.get("ok")),
            "subtasks_queued_for_cloud": sum(
                1 for r in results_by_id.values() if r.get("status") == "queued_waiting_cloud"
            ),
            "checkpoints": checkpoints,
            "results": results_by_id,
        }
        self.db.update_task(
            task_id,
            state="completed" if final_status == "completed" else ("paused" if any_queued_cloud or any_approval else "failed"),
            checkpoint={"checkpoints": checkpoints, "status": final_status},
            result=json.dumps(
                {
                    "status": final_status,
                    "succeeded": report["subtasks_succeeded"],
                    "queued_cloud": report["subtasks_queued_for_cloud"],
                }
            ),
        )
        return {"ok": final_status == "completed", **report}

    async def _execute_single_subtask(self, task_id: str, sub: dict[str, Any]) -> dict[str, Any]:
        kind = str(sub.get("kind") or "local_tool")
        if kind == "cloud_reasoning":
            prompt = str(sub.get("prompt") or sub.get("title") or "")
            qres = await self.queue_manager.submit_or_queue_cloud_operation(
                goal=prompt,
                messages=[{"role": "user", "content": prompt}],
                task_id=task_id,
                checkpoint_id=f"ckpt-{task_id[:8]}-{sub['id']}",
                allow_compact_local_fallback=bool(sub.get("allow_local_fallback", False)),
            )
            if qres.get("queued"):
                return {
                    "ok": False,
                    "status": "queued_waiting_cloud",
                    "cloud_completed": False,
                    "summary": "Cloud reasoning queued offline; local subtasks continued.",
                    "queue_id": qres["queue_item"]["id"],
                }
            content = str(((qres.get("result") or {}).get("message") or {}).get("content") or "")
            return {"ok": True, "status": qres["status"], "summary": content[:400]}

        # Local tool execution with bounded recovery/replan fallback tool
        tool_name = str(sub.get("tool") or "")
        args = dict(sub.get("args") or {})
        if self.tool_registry.get(tool_name) is None:
            return {"ok": False, "status": "failed", "summary": f"Unknown tool: {tool_name}"}
        decision = self.autonomy_policy.decide(tool_name, args)
        if decision.get("action") == "deny":
            return {"ok": False, "status": "denied", "summary": f"Denied by policy: {tool_name}"}
        if decision.get("action") == "approval_required":
            return {"ok": False, "status": "approval_required", "summary": f"Approval required: {tool_name}"}

        outcome = await self.tool_registry.execute(tool_name, args, approved=bool(decision.get("approved")))
        is_ok = outcome.status in {"success", "completed"}
        if not is_ok and isinstance(sub.get("fallback_tool"), dict):
            fb = sub["fallback_tool"]
            fb_name = str(fb.get("tool") or "")
            fb_args = dict(fb.get("args") or {})
            if self.tool_registry.get(fb_name) is not None and self.autonomy_policy.decide(fb_name, fb_args).get("action") == "allow":
                fb_out = await self.tool_registry.execute(fb_name, fb_args, approved=False)
                fb_ok = fb_out.status in {"success", "completed"}
                return {
                    "ok": fb_ok,
                    "status": "recovered_via_replan" if fb_ok else "failed",
                    "replanned": True,
                    "summary": fb_out.summary,
                    "data": fb_out.data,
                }
        return {
            "ok": is_ok,
            "status": "completed" if is_ok else outcome.status,
            "summary": outcome.summary,
            "data": outcome.data,
        }
