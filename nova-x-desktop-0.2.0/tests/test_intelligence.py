from __future__ import annotations

import pytest

from nova.engine import TaskEngine
from nova.intelligence import IntelligenceOrchestrator, ModelManager
from nova.model_providers import ModelCatalog
from nova.provider import ProviderConfigurationError, ProviderError
from tests.conftest import FakeProvider, msg


def add_profiles(manager: ModelManager, count: int = 3, **overrides):
    profiles = []
    for index in range(count):
        data = {
            "name": f"Test model {index + 1}",
            "provider_type": "openai_compatible",
            "base_url": "https://api.openai.com/v1",
            "model_id": f"model-current-{index + 1}",
            "api_key_env": "AI_API_KEY",
            "capabilities": ["chat", "tools"],
            "context_window": 0,
            "input_cost_per_million": None,
            "output_cost_per_million": None,
            "priority": 50 + index,
            "enabled": True,
            "is_default": index == 0,
        }
        data.update(overrides)
        profiles.append(manager.create_profile(data))
    return profiles


@pytest.mark.asyncio
async def test_frontier_fusion_runs_bounded_analyses_review_and_synthesis(environment):
    settings, db, _registry, _workspace = environment
    provider = FakeProvider([msg(f"Candidate answer {index}") for index in range(5)])
    manager = ModelManager(settings, db, injected_provider=provider)
    profiles = add_profiles(manager)
    orchestrator = IntelligenceOrchestrator(manager, settings, db)

    result = await orchestrator.chat(
        [{"role": "system", "content": "Answer concisely."}, {"role": "user", "content": "Compare these possibilities."}],
        mode="frontier_fusion", model_ids=[item["id"] for item in profiles],
    )

    assert result["message"]["content"] == "Candidate answer 4"
    assert result["usage"]["provider_requests"] == 5
    assert result["usage"]["usage_complete"] is True
    assert result["intelligence"]["usage_complete"] is True
    assert result["intelligence"]["mode_effective"] == "frontier_fusion"
    assert result["intelligence"]["cost_estimate_complete"] is False
    assert len(result["intelligence"]["model_results"]) == 4
    assert any(item["role"] == "conflict_review" for item in result["intelligence"]["model_results"])
    assert "no majority vote" in result["intelligence"]["checks_performed"][2]
    assert len(provider.calls) == 5
    history = db.list_intelligence_runs()
    assert history[0]["provider_requests"] == 5
    assert "Candidate answer" not in str(history[0]["details"])


@pytest.mark.asyncio
async def test_real_tool_routing_requires_identity_matched_tool_eval(environment, monkeypatch):
    settings, db, _registry, _workspace = environment
    monkeypatch.setenv("OPENAI_API_KEY", "not-a-real-key")
    manager = ModelManager(settings, db)
    profile = manager.create_profile({
        "name": "Tool-gated model", "provider_type": "openai", "base_url": "https://api.openai.com/v1",
        "model_id": "tool-capable-model", "api_key_env": "OPENAI_API_KEY", "capabilities": ["chat", "tools"],
    })
    raw = manager.get_raw_profile(profile["id"])
    fingerprint = manager._profile_fingerprint(raw)
    db.record_profile_catalog_status(profile["id"], "available", fingerprint)
    tool_schema = [{"type": "function", "function": {"name": "math.calculate"}}]
    orchestrator = IntelligenceOrchestrator(manager, settings, db)

    class FakeAdapter:
        def __init__(self):
            self.calls = 0

        async def chat(self, **_kwargs):
            self.calls += 1
            return msg(None, [{
                "id": "call", "type": "function",
                "function": {"name": "math.calculate", "arguments": '{"expression":"2+2"}'},
            }])

    adapter = FakeAdapter()
    monkeypatch.setattr("nova.intelligence.create_adapter", lambda *_args, **_kwargs: adapter)
    with pytest.raises(ProviderConfigurationError, match="synthetic tool-call evaluation"):
        await orchestrator.chat(
            [{"role": "user", "content": "Calculate 2+2."}], mode="balanced",
            model_ids=[profile["id"]], tools=tool_schema,
        )
    assert adapter.calls == 0

    db.record_profile_tool_test(profile["id"], "passed", fingerprint)
    result = await orchestrator.chat(
        [{"role": "user", "content": "Calculate 2+2."}], mode="balanced",
        model_ids=[profile["id"]], tools=tool_schema,
    )
    assert result["message"]["tool_calls"]
    assert adapter.calls == 1


@pytest.mark.asyncio
async def test_fusion_tool_turn_reports_single_model_degradation(environment):
    settings, db, _registry, _workspace = environment
    tool_call = msg(None, [{
        "id": "tool-call", "type": "function",
        "function": {"name": "math.calculate", "arguments": '{"expression":"2+2"}'},
    }])
    provider = FakeProvider([tool_call])
    manager = ModelManager(settings, db, injected_provider=provider)
    profile = add_profiles(manager, count=1)[0]
    result = await IntelligenceOrchestrator(manager, settings, db).chat(
        [{"role": "user", "content": "Calculate two plus two."}],
        mode="frontier_fusion", model_ids=[profile["id"]], tools=[{"type": "function", "function": {"name": "math.calculate"}}],
    )
    assert result["intelligence"]["mode_requested"] == "frontier_fusion"
    assert result["intelligence"]["mode_effective"] == "balanced"
    assert result["intelligence"]["provider_requests"] == 1
    assert "one declared tool-capable" in result["intelligence"]["degraded_reason"]
    assert len(provider.calls) == 1


@pytest.mark.asyncio
async def test_failed_conflict_review_is_not_reported_as_completed(environment):
    settings, db, _registry, _workspace = environment

    class FailsConflictReview:
        def __init__(self):
            self.calls = 0

        async def chat(self, messages, tools=None):
            self.calls += 1
            if self.calls == 3:
                raise ProviderError("review provider unavailable")
            return msg(f"stage {self.calls}")

    provider = FailsConflictReview()
    manager = ModelManager(settings, db, injected_provider=provider)
    profiles = add_profiles(manager, count=2)
    result = await IntelligenceOrchestrator(manager, settings, db).chat(
        [{"role": "user", "content": "Compare two independent analyses."}],
        mode="frontier_fusion", model_ids=[item["id"] for item in profiles],
    )
    intelligence = result["intelligence"]
    assert intelligence["mode_effective"] == "frontier_fusion_partial"
    assert "targeted cross-model disagreement review" not in intelligence["checks_performed"]
    assert "integrated synthesis; no majority vote" in intelligence["checks_performed"]
    assert any(item["role"] == "conflict_review" and item["status"] == "failed" for item in intelligence["models"])
    assert any("review failed" in warning.lower() for warning in intelligence["warnings"])


@pytest.mark.asyncio
async def test_maximum_intelligence_uses_seven_requests_at_three_model_cap(environment):
    settings, db, _registry, _workspace = environment
    provider = FakeProvider([msg(f"Stage output {index}") for index in range(7)])
    manager = ModelManager(settings, db, injected_provider=provider)
    profiles = add_profiles(manager)
    result = await IntelligenceOrchestrator(manager, settings, db).chat(
        [{"role": "user", "content": "Give a careful response."}],
        mode="maximum_intelligence", model_ids=[item["id"] for item in profiles],
    )
    assert result["intelligence"]["mode_effective"] == "maximum_intelligence"
    assert result["usage"]["provider_requests"] == 7
    assert len(provider.calls) == 7
    roles = [item["role"] for item in result["intelligence"]["models"]]
    assert "targeted_critique" in roles and "revision" in roles


@pytest.mark.asyncio
async def test_request_budget_degrades_fusion_instead_of_fanning_out(environment):
    settings, db, _registry, _workspace = environment
    provider = FakeProvider([msg("single fallback")])
    manager = ModelManager(settings, db, injected_provider=provider)
    profiles = add_profiles(manager)
    result = await IntelligenceOrchestrator(manager, settings, db).chat(
        [{"role": "user", "content": "A small task."}], mode="maximum_intelligence",
        model_ids=[item["id"] for item in profiles], max_provider_requests=2,
    )
    assert result["message"]["content"] == "single fallback"
    assert result["intelligence"]["mode_requested"] == "maximum_intelligence"
    assert result["intelligence"]["mode_effective"] == "balanced"
    assert "budget" in result["intelligence"]["degraded_reason"].lower()
    assert len(provider.calls) == 1


@pytest.mark.asyncio
async def test_primary_failure_uses_only_one_configured_fallback(environment):
    settings, db, _registry, _workspace = environment

    class FailsOnce:
        def __init__(self):
            self.calls = 0

        async def chat(self, messages, tools=None):
            self.calls += 1
            if self.calls == 1:
                raise ProviderError("temporary primary error")
            return msg("fallback completed")

    provider = FailsOnce()
    manager = ModelManager(settings, db, injected_provider=provider)
    profiles = add_profiles(manager, count=3)
    result = await IntelligenceOrchestrator(manager, settings, db).chat(
        [{"role": "user", "content": "Use bounded fallback."}], mode="balanced",
        model_ids=[item["id"] for item in profiles],
    )
    assert result["message"]["content"] == "fallback completed"
    assert provider.calls == 2
    assert result["intelligence"]["provider_requests"] == 2
    assert result["intelligence"]["strategy"] == "capability_aware_fallback"
    assert result["intelligence"]["cost_estimate_complete"] is False


@pytest.mark.asyncio
async def test_configured_cost_ceiling_blocks_over_budget_fusion_before_call(environment):
    settings, db, _registry, _workspace = environment
    settings = type(settings)(**{**settings.__dict__, "max_fusion_budget_usd": 0.000001})
    provider = FakeProvider([])
    manager = ModelManager(settings, db, injected_provider=provider)
    profiles = add_profiles(manager, count=2, input_cost_per_million=100.0, output_cost_per_million=100.0)
    orchestrator = IntelligenceOrchestrator(manager, settings, db)
    with pytest.raises(ProviderError, match="exceeds the configured"):
        await orchestrator.chat(
            [{"role": "user", "content": "A fairly short request."}], mode="frontier_fusion",
            model_ids=[item["id"] for item in profiles],
        )
    assert not provider.calls


@pytest.mark.asyncio
async def test_versioned_eval_suite_measures_format_and_tool_call_without_execution(environment):
    settings, db, _registry, _workspace = environment
    tool_message = msg(None, [{
        "id": "eval-call", "type": "function",
        "function": {"name": "nova_eval_add", "arguments": '{"a":2,"b":4}'},
    }])
    provider = FakeProvider([msg("NOVA_EVAL_OK"), msg('{"ok":true,"value":6}'), tool_message])
    manager = ModelManager(settings, db, injected_provider=provider)
    profile = add_profiles(manager, count=1, capabilities=["chat"])[0]
    result = await manager.evaluate(profile["id"])
    assert result["suite_version"] == "nova-eval-v1"
    assert result["score"] == 100
    assert result["provider_requests"] == 3
    assert result["usage_complete"] is True
    assert all(item["passed"] for item in result["cases"])
    assert len(provider.calls) == 3
    assert manager.get_profile(profile["id"])["tools_test_status"] == "passed"
    updated = manager.update_profile(profile["id"], {"capabilities": ["chat", "tools"]})
    assert updated["tools_test_status"] == "passed"
    assert db.list_eval_runs(profile["id"])[0]["status"] == "passed"


@pytest.mark.asyncio
async def test_identifier_only_catalog_requires_inference_test_before_routing(environment, monkeypatch):
    settings, db, _registry, _workspace = environment
    monkeypatch.setenv("OPENAI_API_KEY", "not-a-real-key")
    manager = ModelManager(settings, db)
    profile = manager.create_profile({
        "name": "Identifier-only catalog model", "provider_type": "openai",
        "base_url": "https://api.openai.com/v1", "model_id": "chat-model-id",
        "api_key_env": "OPENAI_API_KEY", "capabilities": ["chat"],
    })

    class CatalogAndChatAdapter:
        async def list_models(self, **_kwargs):
            return ModelCatalog([{"id": "chat-model-id", "display_name": "Listed name", "capabilities": []}], complete=True)

        async def chat(self, **_kwargs):
            return msg("NOVA_CONNECTION_OK")

    monkeypatch.setattr("nova.intelligence.create_adapter", lambda *_args, **_kwargs: CatalogAndChatAdapter())
    catalog = await manager.list_catalog(profile["id"])
    listed = manager.get_profile(profile["id"])
    assert catalog["availability_status"] == "listed_unverified"
    assert listed["connected"] is True
    assert listed["available"] is False
    assert listed["status"] == "catalog_listed"
    tested = await manager.test_connection(profile["id"])
    after_test = manager.get_profile(profile["id"])
    assert tested["tested"] is True
    assert after_test["tested"] is True and after_test["available"] is True


@pytest.mark.asyncio
async def test_incomplete_catalog_does_not_mark_absent_identifier_unavailable(environment, monkeypatch):
    settings, db, _registry, _workspace = environment
    manager = ModelManager(settings, db, injected_provider=FakeProvider([]))
    profile = add_profiles(manager, count=1)[0]

    class CatalogAdapter:
        async def list_models(self, **_kwargs):
            return ModelCatalog([{"id": "some-other-model", "display_name": "Other"}], complete=False)

    monkeypatch.setattr("nova.intelligence.create_adapter", lambda *_args, **_kwargs: CatalogAdapter())
    result = await manager.list_catalog(profile["id"])
    assert result["catalog_complete"] is False
    assert result["availability_status"] == "catalog_incomplete"
    assert manager.get_profile(profile["id"])["available"] is True  # test adapter is explicitly injected


def test_custom_endpoints_require_explicit_opt_in_and_authentication(environment):
    settings, db, _registry, _workspace = environment
    manager = ModelManager(settings, db)
    default_endpoint_settings = type(settings)(**{
        **settings.__dict__, "ai_base_url": "https://custom.example/v1", "ai_model": "model-id",
    })
    assert "official API host" in ModelManager(default_endpoint_settings, db).get_profile("env-default")["endpoint_error"]
    authorized_default_settings = type(settings)(**{
        **default_endpoint_settings.__dict__, "allow_custom_provider_endpoints": True, "access_token": "owner-only-token",
    })
    assert ModelManager(authorized_default_settings, db).get_profile("env-default")["endpoint_error"] == ""
    with pytest.raises(ValueError, match="official API host"):
        manager.create_profile({
            "name": "Custom", "provider_type": "openai_compatible", "base_url": "https://custom.example/v1",
            "model_id": "model-id", "api_key_env": "AI_API_KEY", "capabilities": ["chat"],
        })
    custom_settings = type(settings)(**{
        **settings.__dict__, "allow_custom_provider_endpoints": True, "access_token": "owner-only-token",
    })
    authorized = ModelManager(custom_settings, db).create_profile({
        "name": "Authorized custom", "provider_type": "openai_compatible", "base_url": "https://custom.example/v1",
        "model_id": "model-id", "api_key_env": "CUSTOM_PROVIDER_KEY", "capabilities": ["chat"],
    })
    assert authorized["base_url"] == "https://custom.example/v1"
    assert authorized["api_key_env"] == "CUSTOM_PROVIDER_KEY"


def test_model_registry_distinguishes_configured_connected_available_and_tested(environment, monkeypatch):
    settings, db, _registry, _workspace = environment
    settings = type(settings)(**{**settings.__dict__, "ai_base_url": "https://api.openai.com/v1"})
    monkeypatch.delenv("AI_API_KEY", raising=False)
    manager = ModelManager(settings, db)
    initial = manager.get_profile("env-default")
    assert initial["configured"] is False
    assert initial["connected"] is False
    assert initial["available"] is False
    assert initial["tested"] is False

    monkeypatch.setenv("AI_API_KEY", "not-a-real-key")
    configured = manager.get_profile("env-default")
    assert configured["configured"] is True
    assert configured["connected"] is False
    assert configured["available"] is False
    fingerprint = manager._profile_fingerprint(manager.get_raw_profile("env-default"))
    db.record_profile_catalog_status("env-default", "available", fingerprint)
    connected = manager.get_profile("env-default")
    assert connected["connected"] is True and connected["available"] is True
    assert connected["tested"] is False
    db.record_profile_test("env-default", "inference_ok", 12.0, config_fingerprint=fingerprint)
    tested = manager.get_profile("env-default")
    assert tested["tested"] is True


def test_model_identity_change_invalidates_stale_catalog_and_test_status(environment, monkeypatch):
    settings, db, _registry, _workspace = environment
    settings = type(settings)(**{**settings.__dict__, "ai_base_url": "https://api.openai.com/v1"})
    monkeypatch.setenv("AI_API_KEY", "not-a-real-key")
    manager = ModelManager(settings, db)
    profile = manager.get_raw_profile("env-default")
    fingerprint = manager._profile_fingerprint(profile)
    db.record_profile_catalog_status("env-default", "available", fingerprint)
    db.record_profile_test("env-default", "inference_ok", 9.0, config_fingerprint=fingerprint)
    assert manager.get_profile("env-default")["available"] is True

    changed_settings = type(settings)(**{**settings.__dict__, "ai_model": "different-model-id"})
    changed = ModelManager(changed_settings, db).get_profile("env-default")
    assert changed["available"] is False
    assert changed["connected"] is False
    assert changed["tested"] is False
    assert changed["last_latency_ms"] is None


def test_unknown_usage_is_not_reported_as_zero_cost(environment):
    settings, db, _registry, _workspace = environment
    manager = ModelManager(settings, db)
    profile = {"input_cost_per_million": 1.0, "output_cost_per_million": 2.0}
    assert manager._estimate_cost(profile, 0, 0) is None
    assert manager._estimate_cost(profile, 1000, 500) == pytest.approx(0.002)


@pytest.mark.asyncio
async def test_provider_without_usage_metadata_is_reported_as_incomplete(environment):
    settings, db, _registry, _workspace = environment

    class NoUsage:
        async def chat(self, messages, tools=None):
            return {"message": {"role": "assistant", "content": "Response without usage data."}}

    manager = ModelManager(settings, db, injected_provider=NoUsage())
    profile = add_profiles(manager, count=1, input_cost_per_million=1.0, output_cost_per_million=2.0)[0]
    result = await manager.chat(profile["id"], [{"role": "user", "content": "Test usage reporting."}])
    assert result["usage"]["usage_reported"] is False
    assert result["model_usage"]["estimated_cost_usd"] is None


def test_model_registry_never_accepts_raw_api_key_fields(environment):
    settings, db, _registry, _workspace = environment
    manager = ModelManager(settings, db)
    with pytest.raises(ValueError, match="environment-variable"):
        manager.create_profile({
            "name": "Unsafe profile", "provider_type": "openai_compatible",
            "base_url": "https://api.openai.com/v1", "model_id": "dynamic-model",
            "api_key_env": "not a variable name", "capabilities": ["chat"],
        })
    assert db.list_model_profiles() == []
