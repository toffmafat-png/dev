"""§2 Unified Cloud Frontier AI Gateway & §3 9-Role Evidence-Verified Frontier Model Fusion."""
from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any

from nova.config import Settings
from nova.db import Database
from nova.hybrid_cloud.architecture import UntrustedExternalInputValidator
from nova.hybrid_cloud.privacy_gateway import CloudPrivacyGateway
from nova.intelligence import VALID_MODES, IntelligenceOrchestrator, ModelManager
from nova.model_providers import (
    PROVIDER_CATALOG,
    create_adapter,
    register_dynamic_provider_spec,
    unregister_dynamic_provider_spec,
)
from nova.provider import ProviderConfigurationError, ProviderError

SPECIALIST_ROLES: tuple[str, ...] = (
    "lead_reasoning",
    "independent_analysis",
    "coding",
    "research",
    "mathematics",
    "critical_review",
    "security_review",
    "verification",
    "final_synthesis",
)

HARDCODED_OUTDATED_MODEL_IDS: tuple[str, ...] = ()

_ROLE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "coding": ("code", "python", "function", "bug", "refactor", "test", "compile", "api", "script", "class"),
    "mathematics": ("calculate", "equation", "math", "proof", "matrix", "probability", "integral", "sum", "+", "*", "/"),
    "research": ("research", "compare", "documentation", "source", "evidence", "literature", "investigate"),
    "security_review": ("security", "vulnerability", "cve", "privilege", "auth", "permission", "firewall", "kali", "audit"),
}


class UnifiedCloudFrontierGateway:
    """§2 Unified local gateway to official Cloud Frontier APIs + optional quantized local fallback."""

    def __init__(
        self,
        *,
        settings: Settings,
        db: Database,
        model_manager: ModelManager,
        orchestrator: IntelligenceOrchestrator,
        privacy_gateway: CloudPrivacyGateway,
        validator: UntrustedExternalInputValidator | None = None,
    ):
        self.settings = settings
        self.db = db
        self.model_manager = model_manager
        self.orchestrator = orchestrator
        self.privacy_gateway = privacy_gateway
        self.validator = validator or UntrustedExternalInputValidator()

    def sync_dynamic_providers_from_db(self) -> list[dict[str, Any]]:
        loaded: list[dict[str, Any]] = []
        for spec in self.db.list_dynamic_provider_specs():
            try:
                loaded.append(register_dynamic_provider_spec(spec))
            except ValueError:
                continue
        return loaded

    def register_provider(self, spec: dict[str, Any]) -> dict[str, Any]:
        registered = register_dynamic_provider_spec(spec)
        saved = self.db.upsert_dynamic_provider_spec(
            {
                **spec,
                "provider_type": registered["provider_type"],
                "official_host": registered.get("official_host", ""),
            }
        )
        return {**registered, "persisted": bool(saved)}

    def remove_provider(self, provider_type: str) -> bool:
        unregister_dynamic_provider_spec(provider_type)
        return self.db.delete_dynamic_provider_spec(provider_type)

    def model_lifecycle_inventory(self) -> dict[str, Any]:
        """§2 Explicitly distinguish configured, connected, available, tested, and actually_used models."""
        self.sync_dynamic_providers_from_db()
        profiles = self.model_manager.list_profiles()
        buckets: dict[str, list[str]] = {
            "configured": [],
            "connected": [],
            "available": [],
            "tested": [],
            "actually_used": [],
        }
        for p in profiles:
            pid = str(p["id"])
            if p.get("configured"):
                buckets["configured"].append(pid)
            if p.get("connected"):
                buckets["connected"].append(pid)
            if p.get("available"):
                buckets["available"].append(pid)
            if p.get("tested"):
                buckets["tested"].append(pid)
            if p.get("actually_used"):
                buckets["actually_used"].append(pid)
        return {
            "hardcoded_model_ids": list(HARDCODED_OUTDATED_MODEL_IDS),
            "provider_count": len(PROVIDER_CATALOG),
            "providers": self.model_manager.provider_catalog(),
            "profile_count": len(profiles),
            "lifecycle_buckets": buckets,
            "lifecycle_counts": {k: len(v) for k, v in buckets.items()},
            "profiles": profiles,
        }

    async def gateway_chat(
        self,
        messages: list[dict[str, Any]],
        *,
        task_id: str = "",
        project_key: str = "",
        included_files: list[str] | None = None,
        included_categories: list[str] | None = None,
        task_allowed_files: list[str] | None = None,
        sensitive_transfer_approved: bool = False,
        preferred_profile_ids: list[str] | None = None,
        tools: list[dict[str, Any]] | None = None,
        response_format: dict[str, Any] | None = None,
        local_task_failed: bool = False,
    ) -> dict[str, Any]:
        """Execute a privacy-gated frontier call with automatic compatible fallback and anti-escalation check."""
        candidates = self._eligible_candidates(preferred_profile_ids, require_tools=bool(tools))
        if not candidates:
            raise ProviderConfigurationError("No available model profile matches the requested capabilities.")

        errors: list[dict[str, str]] = []
        for idx, profile in enumerate(candidates[:2]):
            is_fallback = idx > 0
            gate = self.privacy_gateway.inspect_and_prepare_outbound(
                provider_type=str(profile["provider_type"]),
                model_id=str(profile["model_id"]),
                base_url=str(profile["base_url"]),
                messages=messages,
                task_id=task_id or f"gw-{int(time.time() * 1000)}",
                project_key=project_key,
                included_files=included_files,
                included_categories=included_categories,
                task_allowed_files=task_allowed_files,
                sensitive_transfer_approved=sensitive_transfer_approved,
                is_fallback=is_fallback,
                local_task_failed=local_task_failed,
            )
            if not gate["permitted"]:
                raise ProviderConfigurationError(f"Blocked by Cloud Privacy Gateway ({gate['decision']}): {gate['reason']}")

            try:
                result = await self._invoke_single_profile(
                    profile,
                    gate["sanitized_messages"],
                    tools=tools,
                    response_format=response_format,
                )
                checked = self.validator.validate_model_message(result.get("message") or {})
                return {
                    **result,
                    "message": checked["sanitized_message"],
                    "validation": {
                        "valid": checked["valid"],
                        "violations": checked["violations"],
                        "blocked_tool_calls": checked["blocked_tool_calls"],
                    },
                    "privacy_gate": {
                        "decision": gate["decision"],
                        "payload_chars": gate["payload_chars"],
                        "redacted_items_count": gate["redacted_items_count"],
                        "ledger_id": gate["ledger_entry"].get("id", ""),
                    },
                    "fallback_used": is_fallback,
                    "prior_failures": errors,
                }
            except ProviderError as exc:
                errors.append({"profile_id": str(profile["id"]), "error": str(exc)})
                if not exc.retryable and idx + 1 >= len(candidates[:2]):
                    raise
        raise ProviderError(errors[-1]["error"] if errors else "All candidate frontier models failed.")

    async def stream_chat(
        self,
        messages: list[dict[str, Any]],
        *,
        task_id: str = "",
        project_key: str = "",
        included_files: list[str] | None = None,
        preferred_profile_ids: list[str] | None = None,
    ):
        """§2 Stream responses through the privacy gateway and untrusted-output validator."""
        candidates = self._eligible_candidates(preferred_profile_ids, require_tools=False)
        if not candidates:
            raise ProviderConfigurationError("No available model profile is configured for streaming.")
        profile = candidates[0]
        gate = self.privacy_gateway.inspect_and_prepare_outbound(
            provider_type=str(profile["provider_type"]),
            model_id=str(profile["model_id"]),
            base_url=str(profile["base_url"]),
            messages=messages,
            task_id=task_id or f"stream-{int(time.time() * 1000)}",
            project_key=project_key,
            included_files=included_files,
            included_categories=["prompt"],
        )
        if not gate["permitted"]:
            raise ProviderConfigurationError(f"Streaming blocked by Cloud Privacy Gateway: {gate['reason']}")

        raw_profile = self.model_manager.get_raw_profile(str(profile["id"])) or profile
        if self.model_manager.injected_provider is not None:
            res = await self.model_manager.chat(str(profile["id"]), gate["sanitized_messages"])
            checked = self.validator.validate_model_message(res.get("message") or {})
            text = str(checked["sanitized_message"].get("content") or "")
            for pos in range(0, len(text), 48):
                yield {"delta": text[pos : pos + 48], "done": False, "profile_id": profile["id"]}
            yield {
                "delta": "",
                "done": True,
                "profile_id": profile["id"],
                "message": checked["sanitized_message"],
                "usage": res.get("usage", {}),
            }
            return

        adapter = create_adapter(
            str(raw_profile["provider_type"]),
            self.settings.ai_timeout_seconds,
            self.model_manager.allow_local_http,
            base_url=str(raw_profile["base_url"]),
        )
        started = time.perf_counter()
        try:
            async for chunk in adapter.stream_chat(
                api_key_env=str(raw_profile["api_key_env"]),
                base_url=str(raw_profile["base_url"]),
                model_id=str(raw_profile["model_id"]),
                messages=gate["sanitized_messages"],
                tools=None,
                max_output_tokens=self.settings.max_fusion_output_tokens,
            ):
                if chunk.get("done"):
                    latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
                    self.db.record_profile_call(str(profile["id"]), True, latency_ms, "")
                    checked = self.validator.validate_model_message(chunk.get("message") or {})
                    yield {
                        **chunk,
                        "profile_id": profile["id"],
                        "latency_ms": latency_ms,
                        "message": checked["sanitized_message"],
                    }
                else:
                    yield {**chunk, "profile_id": profile["id"]}
        except ProviderError as exc:
            latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
            self.db.record_profile_call(str(profile["id"]), False, latency_ms, str(exc))
            raise

    async def structured_chat(
        self,
        messages: list[dict[str, Any]],
        *,
        json_schema: dict[str, Any],
        schema_name: str = "structured_response",
        task_id: str = "",
        project_key: str = "",
        preferred_profile_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """§2 Request and validate strict JSON structured outputs against a JSON schema."""
        required_keys = list(json_schema.get("required") or [])
        properties = json_schema.get("properties") if isinstance(json_schema.get("properties"), dict) else {}
        schema_instruction = {
            "role": "system",
            "content": (
                f"Return ONLY a valid JSON object matching schema '{schema_name}': "
                f"{json.dumps(json_schema, sort_keys=True)}"
            ),
        }
        response_format = {
            "type": "json_schema",
            "json_schema": {"name": schema_name, "strict": True, "schema": json_schema},
        }
        result = await self.gateway_chat(
            [schema_instruction, *messages],
            task_id=task_id,
            project_key=project_key,
            preferred_profile_ids=preferred_profile_ids,
            response_format=response_format,
        )
        raw_text = str((result.get("message") or {}).get("content") or "").strip()
        fenced = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw_text, flags=re.IGNORECASE).strip()
        try:
            parsed = json.loads(fenced)
        except ValueError as exc:
            raise ProviderError("Model structured output was not valid JSON.") from exc
        if not isinstance(parsed, dict):
            raise ProviderError("Model structured output root must be a JSON object.")
        missing = [k for k in required_keys if k not in parsed]
        if missing:
            raise ProviderError(f"Model structured output missed required keys: {', '.join(missing)}.")
        type_map = {"string": str, "integer": int, "number": (int, float), "boolean": bool, "array": list, "object": dict}
        for prop_name, prop_spec in properties.items():
            if prop_name in parsed and isinstance(prop_spec, dict) and prop_spec.get("type") in type_map:
                expected = type_map[prop_spec["type"]]
                if prop_spec["type"] == "integer" and isinstance(parsed[prop_name], bool):
                    raise ProviderError(f"Property '{prop_name}' expected integer, got boolean.")
                if not isinstance(parsed[prop_name], expected):
                    raise ProviderError(f"Property '{prop_name}' failed type check for '{prop_spec['type']}'.")
        return {**result, "structured_data": parsed, "schema_valid": True}

    def _eligible_candidates(self, preferred_ids: list[str] | None, *, require_tools: bool) -> list[dict[str, Any]]:
        profiles = self.model_manager.list_profiles()
        by_id = {str(p["id"]): p for p in profiles}
        ordered = [by_id[pid] for pid in (preferred_ids or []) if pid in by_id] if preferred_ids else profiles
        out: list[dict[str, Any]] = []
        for p in ordered:
            if not p.get("available"):
                continue
            if require_tools and ("tools" not in (p.get("capabilities") or []) or not p.get("tools_validated")):
                continue
            out.append(p)
        return out

    async def _invoke_single_profile(
        self,
        profile: dict[str, Any],
        messages: list[dict[str, Any]],
        *,
        tools: list[dict[str, Any]] | None = None,
        response_format: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        pid = str(profile["id"])
        raw = self.model_manager.get_raw_profile(pid) or profile
        if response_format and self.model_manager.injected_provider is None and raw.get("provider_type") in {
            "openai",
            "openai_compatible",
            "deepseek",
            "mistral",
            "xai",
        }:
            adapter = create_adapter(
                str(raw["provider_type"]),
                self.settings.ai_timeout_seconds,
                self.model_manager.allow_local_http,
                base_url=str(raw["base_url"]),
            )
            started = time.perf_counter()
            try:
                res = await adapter.chat(
                    api_key_env=str(raw["api_key_env"]),
                    base_url=str(raw["base_url"]),
                    model_id=str(raw["model_id"]),
                    messages=messages,
                    tools=tools,
                    max_output_tokens=self.settings.max_fusion_output_tokens,
                    response_format=response_format,
                )
                latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
                self.db.record_profile_call(pid, True, latency_ms, "")
                return {**res, "profile": self.model_manager.get_profile(pid) or profile, "latency_ms": latency_ms}
            except ProviderError as exc:
                latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
                self.db.record_profile_call(pid, False, latency_ms, str(exc))
                raise
        return await self.model_manager.chat(pid, messages, tools=tools)


class SpecialistFusionCoordinator:
    """§3 Multi-model collaboration across all 9 specialist roles with local evidence verification."""

    MAJORITY_VOTE_USED = False
    SIMPLE_CONCATENATION_USED = False

    def __init__(
        self,
        *,
        gateway: UnifiedCloudFrontierGateway,
        tool_registry: Any | None = None,
        knowledge_store: Any | None = None,
    ):
        self.gateway = gateway
        self.tool_registry = tool_registry
        self.knowledge_store = knowledge_store

    def assign_specialist_roles(
        self,
        objective: str,
        *,
        mode: str = "frontier_fusion",
        requested_profile_ids: list[str] | None = None,
        latency_budget_ms: float | None = None,
        cost_budget_usd: float | None = None,
    ) -> dict[str, Any]:
        """§3 Dynamically assign specialist roles to available models based on task, latency, and cost."""
        mode_key = mode if mode in VALID_MODES else "balanced"
        candidates = self.gateway._eligible_candidates(requested_profile_ids, require_tools=False)
        if latency_budget_ms is not None:
            filtered = [
                p for p in candidates if p.get("last_latency_ms") is None or float(p["last_latency_ms"]) <= latency_budget_ms
            ]
            if filtered:
                candidates = filtered
        if cost_budget_usd is not None:
            affordable = [
                p
                for p in candidates
                if p.get("input_cost_per_million") is None
                or (float(p.get("input_cost_per_million") or 0) * 0.004) <= cost_budget_usd
            ]
            if affordable:
                candidates = affordable

        if not candidates:
            return {"mode": mode_key, "roles": {}, "active_roles": [], "available_candidates": 0}

        lower_goal = (objective or "").lower()
        detected_domains = [
            role for role, kws in _ROLE_KEYWORDS.items() if any(kw in lower_goal for kw in kws)
        ]

        if mode_key == "fast":
            fastest = sorted(candidates, key=lambda p: (p.get("last_latency_ms") is None, p.get("last_latency_ms") or 0, p["priority"]))
            active_roles = ["lead_reasoning"]
            pool = fastest
        elif mode_key == "balanced":
            active_roles = ["lead_reasoning", *(detected_domains[:1]), "verification"]
            pool = candidates
        elif mode_key == "frontier_fusion":
            active_roles = [
                "lead_reasoning",
                "independent_analysis",
                *(detected_domains[:2]),
                "critical_review",
                "final_synthesis",
            ]
            pool = candidates
        else:  # maximum_intelligence — full bounded specialist collaboration
            active_roles = list(SPECIALIST_ROLES)
            pool = candidates

        dedup_roles = list(dict.fromkeys(active_roles))
        assignments: dict[str, dict[str, Any]] = {}
        for idx, role in enumerate(dedup_roles):
            chosen = pool[idx % len(pool)]
            assignments[role] = {
                "profile_id": chosen["id"],
                "model_id": chosen["model_id"],
                "provider_type": chosen["provider_type"],
            }
        return {
            "mode": mode_key,
            "all_supported_roles": list(SPECIALIST_ROLES),
            "active_roles": dedup_roles,
            "roles": assignments,
            "available_candidates": len(candidates),
            "majority_vote_used": False,
            "concatenation_used": False,
        }

    async def collect_local_verification_evidence(
        self,
        objective: str,
        *,
        math_expression: str = "",
        verification_tool: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Gather real local calculation, documentation, and tool evidence to adjudicate model claims."""
        evidence: list[dict[str, Any]] = []

        expr = math_expression.strip()
        if not expr:
            m = re.search(r"(\d+(?:\.\d+)?(?:\s*[\+\-\*\/]\s*\d+(?:\.\d+)?)+)", objective or "")
            if m:
                expr = m.group(1)
        if expr and self.tool_registry is not None and self.tool_registry.get("math.calculate") is not None:
            outcome = await self.tool_registry.execute("math.calculate", {"expression": expr}, approved=False)
            if outcome.status in {"success", "completed"}:
                evidence.append({"kind": "calculation", "expression": expr, "verified_result": outcome.data})

        if self.knowledge_store is not None and hasattr(self.knowledge_store, "search"):
            try:
                hits = self.knowledge_store.search(objective[:160], limit=3)
                if hits:
                    evidence.append(
                        {
                            "kind": "local_documentation",
                            "matches": [
                                {"title": str(h.get("title") or h.get("source") or ""), "score": h.get("score")}
                                for h in hits[:3]
                            ],
                        }
                    )
            except Exception:
                pass

        if (
            isinstance(verification_tool, dict)
            and self.tool_registry is not None
            and verification_tool.get("name")
            and self.tool_registry.get(str(verification_tool["name"])) is not None
        ):
            tname = str(verification_tool["name"])
            tdef = self.tool_registry.get(tname)
            if tdef is not None and getattr(tdef, "autonomy_class", "") == "routine":
                tout = await self.tool_registry.execute(tname, dict(verification_tool.get("args") or {}), approved=False)
                evidence.append({"kind": "tool_execution", "tool": tname, "ok": tout.status in {"success", "completed"}, "summary": tout.summary})

        return {"evidence_count": len(evidence), "items": evidence}

    async def run_specialist_workflow(
        self,
        objective: str,
        *,
        mode: str = "frontier_fusion",
        requested_profile_ids: list[str] | None = None,
        task_id: str = "",
        project_key: str = "",
        math_expression: str = "",
        verification_tool: dict[str, Any] | None = None,
        max_provider_calls: int | None = None,
        latency_budget_ms: float | None = None,
        cost_budget_usd: float | None = None,
    ) -> dict[str, Any]:
        """§3 Run FAST, BALANCED, FUSION, or MAXIMUM INTELLIGENCE collaboration with local evidence verification."""
        plan = self.assign_specialist_roles(
            objective,
            mode=mode,
            requested_profile_ids=requested_profile_ids,
            latency_budget_ms=latency_budget_ms,
            cost_budget_usd=cost_budget_usd,
        )
        if not plan["roles"]:
            raise ProviderConfigurationError("No available frontier models for specialist workflow.")

        call_cap = min(
            int(max_provider_calls or self.gateway.settings.max_intelligence_requests),
            self.gateway.settings.max_intelligence_requests,
        )
        local_evidence = await self.collect_local_verification_evidence(
            objective,
            math_expression=math_expression,
            verification_tool=verification_tool,
        )
        evidence_json = json.dumps(local_evidence["items"], ensure_ascii=False)

        mode_key = plan["mode"]
        role_outputs: list[dict[str, Any]] = []
        calls_made = 0

        if mode_key == "fast":
            lead_pid = plan["roles"]["lead_reasoning"]["profile_id"]
            res = await self.gateway.gateway_chat(
                [{"role": "user", "content": objective}],
                task_id=task_id,
                project_key=project_key,
                preferred_profile_ids=[lead_pid],
            )
            calls_made += 1
            role_outputs.append({"role": "lead_reasoning", "profile_id": lead_pid, "content": res["message"]["content"]})
            final_answer = str(res["message"]["content"] or "")
        elif mode_key == "balanced":
            lead_pid = plan["roles"]["lead_reasoning"]["profile_id"]
            primary = await self.gateway.gateway_chat(
                [{"role": "user", "content": f"{objective}\nVerified local evidence: {evidence_json}"}],
                task_id=task_id,
                project_key=project_key,
                preferred_profile_ids=[lead_pid],
            )
            calls_made += 1
            draft = str(primary["message"]["content"] or "")
            role_outputs.append({"role": "lead_reasoning", "profile_id": lead_pid, "content": draft})

            if calls_made < call_cap and "verification" in plan["roles"]:
                ver_pid = plan["roles"]["verification"]["profile_id"]
                ver_res = await self.gateway.gateway_chat(
                    [
                        {
                            "role": "system",
                            "content": "Verify the draft strictly against the verified local evidence; correct any unsupported or miscalculated claim.",
                        },
                        {
                            "role": "user",
                            "content": f"Objective: {objective}\nVerified evidence: {evidence_json}\nDraft: {draft}",
                        },
                    ],
                    task_id=task_id,
                    project_key=project_key,
                    preferred_profile_ids=[ver_pid],
                )
                calls_made += 1
                final_answer = str(ver_res["message"]["content"] or draft)
                role_outputs.append({"role": "verification", "profile_id": ver_pid, "content": final_answer})
            else:
                final_answer = draft
        else:
            # FUSION & MAXIMUM INTELLIGENCE: parallel independent specialist analyses -> critical/security review -> evidence-adjudicated synthesis
            parallel_roles = [
                r
                for r in plan["active_roles"]
                if r not in {"critical_review", "security_review", "verification", "final_synthesis"}
            ]
            max_parallel = max(1, min(len(parallel_roles), max(1, call_cap - 2), self.gateway.settings.max_fusion_models))
            selected_parallel = parallel_roles[:max_parallel]

            async def _run_role(rname: str) -> dict[str, Any]:
                pid = plan["roles"][rname]["profile_id"]
                resp = await self.gateway.gateway_chat(
                    [
                        {
                            "role": "system",
                            "content": f"Specialist role: {rname}. Analyze independently using verifiable reasoning.",
                        },
                        {"role": "user", "content": f"{objective}\nVerified local evidence: {evidence_json}"},
                    ],
                    task_id=task_id,
                    project_key=project_key,
                    preferred_profile_ids=[pid],
                )
                return {"role": rname, "profile_id": pid, "content": str(resp["message"]["content"] or "")}

            analysts = await asyncio.gather(*(_run_role(r) for r in selected_parallel))
            calls_made += len(analysts)
            role_outputs.extend(analysts)

            review_summary = ""
            for rev_role in ("critical_review", "security_review", "verification"):
                if rev_role in plan["roles"] and calls_made + 1 < call_cap:
                    rev_pid = plan["roles"][rev_role]["profile_id"]
                    rev_resp = await self.gateway.gateway_chat(
                        [
                            {
                                "role": "system",
                                "content": (
                                    f"Role: {rev_role}. Identify factual, mathematical, or security disagreements across "
                                    "specialist analyses. Never use majority vote; adjudicate strictly from verified evidence."
                                ),
                            },
                            {
                                "role": "user",
                                "content": json.dumps(
                                    {
                                        "objective": objective,
                                        "verified_evidence": local_evidence["items"],
                                        "analyses": analysts,
                                    },
                                    ensure_ascii=False,
                                ),
                            },
                        ],
                        task_id=task_id,
                        project_key=project_key,
                        preferred_profile_ids=[rev_pid],
                    )
                    calls_made += 1
                    review_summary = str(rev_resp["message"]["content"] or "")
                    role_outputs.append({"role": rev_role, "profile_id": rev_pid, "content": review_summary})

            synth_pid = plan["roles"].get("final_synthesis", plan["roles"]["lead_reasoning"])["profile_id"]
            synth_resp = await self.gateway.gateway_chat(
                [
                    {
                        "role": "system",
                        "content": (
                            "Role: final_synthesis. Produce a single coherent, evidence-verified response integrating "
                            "specialist findings and resolving disagreements using the verified local evidence—never "
                            "concatenate drafts and never rely on majority voting."
                        ),
                    },
                    {
                        "role": "user",
                        "content": json.dumps(
                            {
                                "objective": objective,
                                "verified_evidence": local_evidence["items"],
                                "analyses": analysts,
                                "review": review_summary,
                            },
                            ensure_ascii=False,
                        ),
                    },
                ],
                task_id=task_id,
                project_key=project_key,
                preferred_profile_ids=[synth_pid],
            )
            calls_made += 1
            final_answer = str(synth_resp["message"]["content"] or "")
            role_outputs.append({"role": "final_synthesis", "profile_id": synth_pid, "content": final_answer})

        return {
            "mode": mode_key,
            "final_answer": final_answer,
            "role_plan": plan,
            "executed_roles": [r["role"] for r in role_outputs],
            "role_outputs_count": len(role_outputs),
            "provider_calls": calls_made,
            "call_budget": call_cap,
            "local_verification_evidence": local_evidence,
            "majority_vote_used": False,
            "concatenation_used": False,
        }
