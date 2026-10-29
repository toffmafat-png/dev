from __future__ import annotations

import httpx
import pytest

from nova.provider import OpenAICompatibleProvider, ProviderConfigurationError


class MockAsyncClient:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def post(self, url, json, headers):
        self.url = url
        self.payload = json
        self.headers = headers
        return httpx.Response(200, json={
            "choices": [{"message": {"role": "assistant", "content": "provider response"}}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 4, "total_tokens": 15},
        })


@pytest.mark.asyncio
async def test_openai_compatible_provider_sends_server_key_and_normalizes_response(environment, monkeypatch):
    settings, _db, _registry, _workspace = environment
    clients = []

    def create_client(**kwargs):
        client = MockAsyncClient(**kwargs)
        clients.append(client)
        return client

    monkeypatch.setattr('nova.provider.httpx.AsyncClient', create_client)
    provider = OpenAICompatibleProvider(settings)
    result = await provider.chat([{"role": "user", "content": "Hello"}], tools=[])
    assert clients[0].url == 'https://unit.test/v1/chat/completions'
    assert clients[0].headers['Authorization'] == 'Bearer test-only-not-a-real-key'
    assert clients[0].payload['model'] == 'test-model'
    assert result['message']['content'] == 'provider response'
    assert result['usage']['total_tokens'] == 15
    assert 'test-only-not-a-real-key' not in str(result)


@pytest.mark.asyncio
async def test_provider_fails_helpfully_without_credentials(environment):
    settings, _db, _registry, _workspace = environment
    settings = type(settings)(**{**settings.__dict__, 'ai_api_key': ''})
    provider = OpenAICompatibleProvider(settings)
    with pytest.raises(ProviderConfigurationError, match='Set AI_API_KEY'):
        await provider.chat([{"role": "user", "content": "Hello"}])
