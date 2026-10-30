"""Tests for DEV Corrected Master Architecture (§1–§11):
Locally Hosted Autonomous AI Platform Powered by Cloud Frontier Intelligence.
"""
from __future__ import annotations

import json
from contextlib import asynccontextmanager

import httpx
import pytest

from nova.hybrid_cloud import (
    CLOUD_INTELLIGENCE_COMPONENTS,
    HYBRID_INVARIANTS,
    LOCAL_HOSTED_COMPONENTS,
    SPECIALIST_ROLES,
    verify_hybrid_architecture_integrity,
)
from nova.hybrid_cloud.acceptance import run_acceptance
from nova.intelligence import IntelligenceOrchestrator, ModelManager
from nova.model_providers import (
    LlamaCppAdapter,
    OpenAICompatibleAdapter,
    check_local_model_resource_fit,
    create_adapter,
)
from nova.provider import ProviderConfigurationError
from tests.conftest import FakeProvider, msg


def test_section1_hybrid_local_cloud_boundary_and_spaces_removal():
    report = verify_hybrid_architecture_integrity()
    assert len(LOCAL_HOSTED_COMPONENTS) == 15
    assert len(CLOUD_INTELLIGENCE_COMPONENTS) == 8
    assert report["huggingface_spaces_frontmatter_removed"] is True
    assert report["companion_asgi_loopback_only_default"] is True
    assert report["container_non_root_and_loopback"] is True
    assert report["multi_provider_no_lock_in"] is True
    assert HYBRID_INVARIANTS["cloud_hosts_application"] is False
    assert HYBRID_INVARIANTS["huggingface_spaces_deployment"] is False
    assert HYBRID_INVARIANTS["competing_execution_engines"] is False


def test_section7_llama_cpp_compact_quantized_ram_and_enormous_model_guard():
    fit_compact = check_local_model_resource_fit(
        "llama-3.2-3b-instruct-q4_k_m.gguf",
        available_ram_mb=8192,
        require_compact_quantized=True,
    )
    assert fit_compact["fits_resource_budget"] is True
    assert fit_compact["is_quantized"] is True
    assert fit_compact["is_enormous"] is False

    fit_enormous = check_local_model_resource_fit(
        "llama-3.1-70b-instruct-q4_k_m.gguf",
        available_ram_mb=131072,
        require_compact_quantized=True,
    )
    assert fit_enormous["fits_resource_budget"] is False
    assert fit_enormous["is_enormous"] is True
    assert "never automatically runs enormous models" in fit_enormous["reason"]

    fit_fp16 = check_local_model_resource_fit(
        "qwen2.5-7b-instruct-fp16.gguf",
        available_ram_mb=65536,
        require_compact_quantized=True,
    )
    assert fit_fp16["fits_resource_budget"] is False
    assert fit_fp16["is_quantized"] is False


@pytest.mark.asyncio
async def test_section7_llama_cpp_adapter_blocks_enormous_and_runs_compact(monkeypatch):
    monkeypatch.delenv("NOVA_FORCE_LARGE_LOCAL_MODEL", raising=False)
    adapter = create_adapter("llama_cpp", 5, allow_local_http=True, base_url="http://127.0.0.1:8080/v1")
    assert isinstance(adapter, LlamaCppAdapter)

    with pytest.raises(ProviderConfigurationError, match="exceeds compact local fallback ceiling"):
        await adapter.chat(
            api_key_env="",
            base_url="http://127.0.0.1:8080/v1",
            model_id="llama-3.1-70b-instruct-q4_k_m.gguf",
            messages=[{"role": "user", "content": "Hello"}],
            tools=None,
            max_output_tokens=64,
        )


@pytest.mark.asyncio
async def test_section2_sse_stream_chat_parses_event_stream(monkeypatch):
    monkeypatch.setenv("UNIT_STREAM_KEY", "stream-key-123")

    class FakeStreamResponse:
        is_error = False
        status_code = 200

        async def aiter_lines(self):
            yield 'data: {"choices":[{"delta":{"content":"Hello "}}]}'
            yield 'data: {"choices":[{"delta":{"content":"Kali!"}}],"usage":{"prompt_tokens":8,"completion_tokens":4,"total_tokens":12}}'
            yield "data: [DONE]"

    class FakeStreamClient:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        @asynccontextmanager
        async def stream(self, _method, _url, **_kwargs):
            yield FakeStreamResponse()

    monkeypatch.setattr(httpx, "AsyncClient", FakeStreamClient)
    adapter = OpenAICompatibleAdapter(5)
    deltas = []
    final_chunk = None
    async for chunk in adapter.stream_chat(
        api_key_env="UNIT_STREAM_KEY",
        base_url="https://api.openai.com/v1",
        model_id="dynamic-stream-model",
        messages=[{"role": "user", "content": "Greet"}],
        tools=None,
        max_output_tokens=64,
    ):
        if chunk["done"]:
            final_chunk = chunk
        else:
            deltas.append(chunk["delta"])

    assert "".join(deltas) == "Hello Kali!"
    assert final_chunk is not None
    assert final_chunk["message"]["content"] == "Hello Kali!"
    assert final_chunk["usage"]["total_tokens"] == 12


@pytest.mark.asyncio
async def test_section2_and_3_five_state_lifecycle_and_nine_specialist_roles(environment, monkeypatch):
    settings, db, registry, _ws = environment
    monkeypatch.setenv("OPENAI_API_KEY", "unit-key-value")
    provider = FakeProvider([msg(f"Specialist output {i}") for i in range(10)])
    manager = ModelManager(settings, db, injected_provider=provider)
    orchestrator = IntelligenceOrchestrator(manager, settings, db)

    p_used = manager.create_profile(
        {
            "name": "Used Frontier Model",
            "provider_type": "openai",
            "base_url": "https://api.openai.com/v1",
            "model_id": "frontier-dynamic-a",
            "api_key_env": "OPENAI_API_KEY",
            "capabilities": ["chat"],
            "is_default": True,
        }
    )
    p_unused = manager.create_profile(
        {
            "name": "Unused Configured Model",
            "provider_type": "openai",
            "base_url": "https://api.openai.com/v1",
            "model_id": "frontier-dynamic-b",
            "api_key_env": "OPENAI_API_KEY",
            "capabilities": ["chat"],
            "is_default": False,
        }
    )
    assert manager.get_profile(p_used["id"])["actually_used"] is False
    await manager.chat(p_used["id"], [{"role": "user", "content": "Ping"}])
    assert manager.get_profile(p_used["id"])["actually_used"] is True
    assert manager.get_profile(p_unused["id"])["actually_used"] is False

    from nova.autonomy import AutonomyPolicy
    from nova.engine import TaskEngine

    engine = TaskEngine(db, orchestrator, registry, settings, AutonomyPolicy(settings, db, registry))
    hc = engine.platform.hybrid_cloud
    plan = hc.fusion.assign_specialist_roles(
        "Solve 15 * 8 + 5, audit Kali permissions, and review Python patch",
        mode="maximum_intelligence",
        requested_profile_ids=[p_used["id"], p_unused["id"]],
    )
    assert set(plan["active_roles"]) == set(SPECIALIST_ROLES)
    assert len(SPECIALIST_ROLES) == 9


def test_section5_privacy_gateway_redaction_local_only_and_anti_escalation(environment):
    settings, db, registry, ws = environment
    from nova.autonomy import AutonomyPolicy
    from nova.engine import TaskEngine

    provider = FakeProvider([msg("ok")])
    mm = ModelManager(settings, db, injected_provider=provider)
    orch = IntelligenceOrchestrator(mm, settings, db)
    engine = TaskEngine(db, orch, registry, settings, AutonomyPolicy(settings, db, registry))
    pg = engine.platform.hybrid_cloud.privacy_gateway

    # 1. Secret redaction
    synth_ant_key = "sk-" + "ant-" + "api03-SECRETTOKEN1234567890"
    outbound = pg.inspect_and_prepare_outbound(
        provider_type="openai",
        model_id="frontier-1",
        base_url="https://api.openai.com/v1",
        messages=[
            {
                "role": "user",
                "content": (
                    f"Key {synth_ant_key} and Cookie: nova_session=mycookie123456 "
                    "and password=topsecretpw!"
                ),
            }
        ],
        task_id="t-sec-1",
        included_files=["main.py"],
        task_allowed_files=["main.py"],
    )
    assert outbound["permitted"] is True
    cleaned = outbound["sanitized_messages"][0]["content"]
    assert "SECRETTOKEN1234567890" not in cleaned
    assert "mycookie123456" not in cleaned
    assert "topsecretpw" not in cleaned

    # 2. Anti-larger-payload fallback guard
    escalated = pg.inspect_and_prepare_outbound(
        provider_type="mistral",
        model_id="mistral-1",
        base_url="https://api.mistral.ai/v1",
        messages=[{"role": "user", "content": "A much larger fallback payload! " * 20}],
        task_id="t-sec-1",
        is_fallback=True,
    )
    assert escalated["permitted"] is False
    assert "larger_fallback_payload_blocked" in escalated["reason"]

    # 3. Local-only project mode
    pg.set_project_local_only("vault-proj", project_path=str(ws / "vault-proj"), local_only=True)
    blocked_cloud = pg.inspect_and_prepare_outbound(
        provider_type="gemini",
        model_id="gemini-dynamic",
        base_url="https://generativelanguage.googleapis.com/v1beta",
        messages=[{"role": "user", "content": "Analyze"}],
        project_key="vault-proj",
    )
    assert blocked_cloud["permitted"] is False
    assert "project_local_only" in blocked_cloud["reason"]

    # Ledger never stores secrets
    ledger_json = json.dumps(db.list_cloud_transmissions(limit=20))
    assert "SECRETTOKEN1234567890" not in ledger_json
    assert "topsecretpw" not in ledger_json


def test_master_hybrid_architecture_acceptance_suite_passes():
    report = run_acceptance()
    assert report["passed"] is True
    assert report["passed_count"] == 15
    assert report["total_count"] == 15
