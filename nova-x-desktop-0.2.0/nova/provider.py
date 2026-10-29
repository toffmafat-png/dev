"""OpenAI-compatible Chat Completions client. API keys stay server-side."""
from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Any

import httpx

from nova.config import Settings


class ProviderError(RuntimeError):
    def __init__(self, message: str, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


class ProviderConfigurationError(ProviderError):
    pass


class OpenAICompatibleProvider:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        if not self.settings.ai_configured:
            raise ProviderConfigurationError(
                "AI provider is not configured. Set AI_API_KEY, AI_BASE_URL, and AI_MODEL on the server, then restart NOVA."
            )
        payload: dict[str, Any] = {
            "model": self.settings.ai_model,
            "messages": messages,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        headers = {
            "Authorization": f"Bearer {self.settings.ai_api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        timeout = httpx.Timeout(float(self.settings.ai_timeout_seconds))
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
                response = await client.post(
                    f"{self.settings.ai_base_url.rstrip('/')}/chat/completions",
                    json=payload,
                    headers=headers,
                )
        except httpx.TimeoutException as exc:
            raise ProviderError("The AI provider timed out.", retryable=True) from exc
        except httpx.RequestError as exc:
            raise ProviderError("Could not connect to the configured AI provider.", retryable=True) from exc

        if response.status_code == 429 or response.status_code >= 500:
            raise ProviderError(
                f"The AI provider returned HTTP {response.status_code}; retry may succeed.", retryable=True
            )
        if response.is_error:
            raise ProviderError(
                f"The AI provider rejected the request (HTTP {response.status_code}). Check the model, endpoint, and credentials."
            )
        try:
            body = response.json()
            message = body["choices"][0]["message"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ProviderError("The AI provider response was not in the expected Chat Completions format.") from exc
        if not isinstance(message, dict):
            raise ProviderError("The AI provider returned an invalid message.")
        usage = body.get("usage") if isinstance(body.get("usage"), dict) else {}
        return {
            "message": message,
            "usage": {
                "prompt_tokens": self._safe_int(usage.get("prompt_tokens")),
                "completion_tokens": self._safe_int(usage.get("completion_tokens")),
                "total_tokens": self._safe_int(usage.get("total_tokens")),
            },
        }

    @staticmethod
    def _safe_int(value: Any) -> int:
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            return 0


class RateLimitedProvider:
    """Process-local sliding-window cap shared by chat and task inference."""

    def __init__(self, provider: Any, requests_per_minute: int):
        self.provider = provider
        self.requests_per_minute = max(1, requests_per_minute)
        self._timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        async with self._lock:
            now = time.monotonic()
            while self._timestamps and now - self._timestamps[0] >= 60:
                self._timestamps.popleft()
            if len(self._timestamps) >= self.requests_per_minute:
                raise ProviderError(
                    f"NOVA's process-wide limit of {self.requests_per_minute} AI requests per minute was reached. Wait briefly and try again."
                )
            self._timestamps.append(now)
        return await self.provider.chat(messages, tools)
