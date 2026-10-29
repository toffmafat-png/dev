from __future__ import annotations

import httpx
import pytest

from nova.model_providers import AnthropicAdapter, GeminiAdapter, OpenAIAdapter, OpenAICompatibleAdapter, create_adapter, validate_base_url
from nova.provider import ProviderError


class MockAsyncClient:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.request_data = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def request(self, method, url, headers, json=None):
        self.request_data = {"method": method, "url": url, "headers": headers, "json": json}
        return httpx.Response(200, json={
            "choices": [{"message": {"role": "assistant", "content": "safe response"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 3, "total_tokens": 13},
        })


@pytest.mark.asyncio
async def test_openai_compatible_adapter_uses_env_secret_and_normalizes(monkeypatch):
    monkeypatch.setenv("UNIT_PROVIDER_KEY", "test-secret-value")
    clients = []

    def factory(**kwargs):
        client = MockAsyncClient(**kwargs)
        clients.append(client)
        return client

    monkeypatch.setattr("nova.model_providers.httpx.AsyncClient", factory)
    adapter = OpenAICompatibleAdapter(5)
    result = await adapter.chat(
        api_key_env="UNIT_PROVIDER_KEY", base_url="https://api.example.test/v1", model_id="dynamic-model-id",
        messages=[{"role": "user", "content": "Hello"}], tools=None, max_output_tokens=128,
    )
    request = clients[0].request_data
    assert request["url"] == "https://api.example.test/v1/chat/completions"
    assert request["headers"]["Authorization"] == "Bearer test-secret-value"
    assert request["json"]["model"] == "dynamic-model-id"
    assert result["usage"]["total_tokens"] == 13
    assert "test-secret-value" not in str(result)


@pytest.mark.asyncio
async def test_openai_native_surface_uses_current_completion_token_parameter(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "unit-openai-key")
    clients = []

    def factory(**kwargs):
        client = MockAsyncClient(**kwargs)
        clients.append(client)
        return client

    monkeypatch.setattr("nova.model_providers.httpx.AsyncClient", factory)
    adapter = OpenAIAdapter(5)
    await adapter.chat(
        api_key_env="OPENAI_API_KEY", base_url="https://api.openai.com/v1", model_id="catalog-selected-id",
        messages=[{"role": "user", "content": "Hi"}], tools=None, max_output_tokens=128,
    )
    payload = clients[0].request_data["json"]
    assert payload["max_completion_tokens"] == 128
    assert "max_tokens" not in payload
    assert isinstance(create_adapter("openai_compatible", 5, base_url="https://api.openai.com/v1"), OpenAIAdapter)


@pytest.mark.asyncio
async def test_provider_retry_after_is_preserved_for_bounded_task_retry(monkeypatch):
    monkeypatch.setenv("UNIT_PROVIDER_KEY", "rate-limit-test-key")

    class RateLimitedClient(MockAsyncClient):
        async def request(self, method, url, headers, json=None):
            return httpx.Response(429, headers={"Retry-After": "3"}, json={"error": "rate limited"})

    monkeypatch.setattr("nova.model_providers.httpx.AsyncClient", lambda **kwargs: RateLimitedClient(**kwargs))
    adapter = OpenAICompatibleAdapter(5)
    with pytest.raises(ProviderError) as caught:
        await adapter.chat(
            api_key_env="UNIT_PROVIDER_KEY", base_url="https://api.example.test/v1", model_id="dynamic-model-id",
            messages=[{"role": "user", "content": "Hello"}], tools=None, max_output_tokens=128,
        )
    assert caught.value.retryable is True
    assert caught.value.retry_after_seconds == 3.0
    assert adapter._retry_after_seconds("2") == 2.0


def test_endpoint_validation_requires_https_except_explicit_loopback():
    assert validate_base_url("https://provider.example/v1") == "https://provider.example/v1"
    with pytest.raises(ValueError, match="HTTPS"):
        validate_base_url("http://provider.example/v1")
    with pytest.raises(ValueError):
        validate_base_url("https://user:pass@provider.example/v1")
    assert validate_base_url("http://localhost:1234/v1", allow_local_http=True) == "http://localhost:1234/v1"


def test_native_provider_message_translation_preserves_tool_flow():
    messages = [
        {"role": "system", "content": "Stay in scope."},
        {"role": "user", "content": "Run the calculation."},
        {"role": "assistant", "content": None, "tool_calls": [{
            "id": "call-1", "type": "function", "function": {"name": "math.calculate", "arguments": '{"expression":"2+2"}'},
        }]},
        {"role": "tool", "tool_call_id": "call-1", "content": "4"},
    ]
    system, anthropic_messages = AnthropicAdapter._to_anthropic(messages)
    assert system == "Stay in scope."
    assert anthropic_messages[1]["content"][0]["type"] == "tool_use"
    assert anthropic_messages[2]["content"][0]["type"] == "tool_result"

    gemini_system, gemini_messages = GeminiAdapter._to_gemini(messages)
    assert gemini_system == "Stay in scope."
    assert gemini_messages[1]["parts"][0]["functionCall"]["name"] == "math.calculate"
    assert gemini_messages[2]["parts"][0]["functionResponse"]["name"] == "math.calculate"
