"""Authorized provider API adapters. Credentials are supplied by NOVA's server-side env."""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import urllib.parse
from typing import Any

import httpx

from nova.provider import ProviderConfigurationError, ProviderError


class ModelCatalog(list[dict[str, Any]]):
    """Provider model list plus completeness metadata for safe identifier validation."""
    def __init__(self, models: list[dict[str, Any]], *, complete: bool = True):
        super().__init__(models)
        self.complete = complete


PROVIDER_CATALOG: dict[str, dict[str, Any]] = {
    "openai": {
        "label": "OpenAI",
        "default_base_url": "https://api.openai.com/v1",
        "key_env_default": "OPENAI_API_KEY",
        "catalog": True,
        "native_adapter": False,
        "note": "Uses OpenAI Chat Completions with the current max_completion_tokens parameter and account-visible model catalog.",
    },
    "openai_compatible": {
        "label": "OpenAI-compatible API",
        "default_base_url": "https://api.openai.com/v1",
        "key_env_default": "AI_API_KEY",
        "catalog": True,
        "native_adapter": False,
        "note": "Uses Chat Completions. For custom endpoints, confirm the operator is authorized and compatible.",
    },
    "anthropic": {
        "label": "Anthropic",
        "default_base_url": "https://api.anthropic.com/v1",
        "key_env_default": "ANTHROPIC_API_KEY",
        "catalog": True,
        "native_adapter": True,
        "note": "Uses the native Messages API and model catalog; tool schemas are translated server-side.",
    },
    "gemini": {
        "label": "Google Gemini API",
        "default_base_url": "https://generativelanguage.googleapis.com/v1beta",
        "key_env_default": "GEMINI_API_KEY",
        "catalog": True,
        "native_adapter": True,
        "note": "Uses the native generateContent API and provider model metadata.",
    },
    "xai": {
        "label": "xAI",
        "default_base_url": "https://api.x.ai/v1",
        "key_env_default": "XAI_API_KEY",
        "catalog": True,
        "native_adapter": False,
        "note": "First adapter uses the documented OpenAI-compatible Chat Completions surface; see integration notes for its API lifecycle limitation.",
    },
    "deepseek": {
        "label": "DeepSeek",
        "default_base_url": "https://api.deepseek.com",
        "key_env_default": "DEEPSEEK_API_KEY",
        "catalog": True,
        "native_adapter": False,
        "note": "Uses the provider's OpenAI-compatible Chat Completions surface and model catalog.",
    },
    "mistral": {
        "label": "Mistral",
        "default_base_url": "https://api.mistral.ai/v1",
        "key_env_default": "MISTRAL_API_KEY",
        "catalog": True,
        "native_adapter": False,
        "note": "Uses the provider's Chat Completions surface and model catalog.",
    },
}


_SECRET_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")


def validate_key_env(value: str) -> str:
    value = value.strip()
    if not _SECRET_ENV_RE.fullmatch(value):
        raise ValueError("Credential reference must be an environment-variable name such as ANTHROPIC_API_KEY.")
    return value


def validate_base_url(value: str, allow_local_http: bool = False) -> str:
    value = value.strip().rstrip("/")
    try:
        parsed = urllib.parse.urlsplit(value)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Provider endpoint is not a valid URL.") from exc
    if not hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Provider endpoint must be an absolute URL without credentials, query, or fragment.")
    if parsed.scheme == "https":
        return value
    local_hosts = {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme == "http" and allow_local_http and hostname.lower() in local_hosts:
        return value
    raise ValueError("Provider endpoints must use HTTPS. HTTP is allowed only for loopback when explicitly enabled by the operator.")


def _safe_int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError, OverflowError):
        return 0


def _error_text(status_code: int) -> str:
    if status_code == 401 or status_code == 403:
        return f"Provider rejected credentials or access (HTTP {status_code}). Check the server-side credential reference and provider access."
    if status_code == 404:
        return "Provider endpoint or model was not found (HTTP 404). Refresh the model catalog and verify the configured model identifier."
    if status_code == 429 or status_code >= 500:
        return f"Provider returned HTTP {status_code}; a bounded retry may succeed."
    return f"Provider rejected the request (HTTP {status_code}). Check the endpoint, request capabilities, and model configuration."


class _HTTPAdapter:
    def __init__(self, timeout_seconds: int, allow_local_http: bool = False):
        self.timeout_seconds = max(5, min(int(timeout_seconds), 180))
        self.allow_local_http = allow_local_http

    def _base(self, base_url: str) -> str:
        return validate_base_url(base_url, self.allow_local_http)

    @staticmethod
    def _retry_after_seconds(value: str | None) -> float | None:
        if not value:
            return None
        try:
            delay = float(value.strip())
        except (TypeError, ValueError, OverflowError):
            try:
                target = parsedate_to_datetime(value)
                if target.tzinfo is None:
                    target = target.replace(tzinfo=timezone.utc)
                delay = (target - datetime.now(timezone.utc)).total_seconds()
            except (TypeError, ValueError, OverflowError):
                return None
        return max(0.0, min(float(delay), 3600.0))

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        timeout = httpx.Timeout(float(self.timeout_seconds))
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
                response = await client.request(method, url, headers=headers, json=json_body)
        except httpx.TimeoutException as exc:
            raise ProviderError("The AI provider timed out.", retryable=True) from exc
        except httpx.RequestError as exc:
            # Do not echo exception strings: URLs can contain operator-controlled details.
            raise ProviderError("Could not connect to the configured AI provider.", retryable=True) from exc
        if response.status_code == 429 or response.status_code >= 500:
            error = ProviderError(_error_text(response.status_code), retryable=True)
            retry_after = self._retry_after_seconds(response.headers.get("Retry-After"))
            if retry_after is not None:
                error.retry_after_seconds = retry_after
            raise error
        if response.is_error:
            raise ProviderError(_error_text(response.status_code))
        try:
            body = response.json()
        except ValueError as exc:
            raise ProviderError("Provider returned a non-JSON response where JSON was expected.") from exc
        if not isinstance(body, dict):
            raise ProviderError("Provider returned an invalid response object.")
        return body

    async def _credential(self, api_key_env: str) -> str:
        key = os.getenv(validate_key_env(api_key_env), "").strip()
        if not key:
            raise ProviderConfigurationError(
                f"Credential is not configured. Set the server-side {api_key_env} environment variable; NOVA does not accept or store keys in the browser."
            )
        return key


class OpenAICompatibleAdapter(_HTTPAdapter):
    token_parameter = "max_tokens"

    async def chat(
        self, *, api_key_env: str, base_url: str, model_id: str,
        messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None,
        max_output_tokens: int,
    ) -> dict[str, Any]:
        key = await self._credential(api_key_env)
        base = self._base(base_url)
        payload: dict[str, Any] = {"model": model_id, "messages": messages, self.token_parameter: max_output_tokens}
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        body = await self._request(
            "POST", f"{base}/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json", "Accept": "application/json"},
            json_body=payload,
        )
        try:
            message = body["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError("Provider response did not contain a Chat Completions message.") from exc
        if not isinstance(message, dict):
            raise ProviderError("Provider returned an invalid message.")
        usage = body.get("usage") if isinstance(body.get("usage"), dict) else {}
        return {
            "message": message,
            "usage": {
                "prompt_tokens": _safe_int(usage.get("prompt_tokens")),
                "completion_tokens": _safe_int(usage.get("completion_tokens")),
                "total_tokens": _safe_int(usage.get("total_tokens")),
            },
        }

    async def list_models(self, *, api_key_env: str, base_url: str) -> ModelCatalog:
        key = await self._credential(api_key_env)
        body = await self._request(
            "GET", f"{self._base(base_url)}/models",
            headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
        )
        models = body.get("data", [])
        if not isinstance(models, list):
            raise ProviderError("Provider model catalog response has an unsupported shape.")
        return ModelCatalog([
            {"id": str(item.get("id", "")), "display_name": str(item.get("name", item.get("id", ""))), "capabilities": []}
            for item in models if isinstance(item, dict) and item.get("id")
        ], complete=not bool(body.get("has_more", False)))


class OpenAIAdapter(OpenAICompatibleAdapter):
    token_parameter = "max_completion_tokens"


class AnthropicAdapter(_HTTPAdapter):
    @staticmethod
    def _to_anthropic(messages: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
        system_parts = [str(item.get("content", "")) for item in messages if item.get("role") == "system"]
        output: list[dict[str, Any]] = []
        for item in messages:
            role = item.get("role")
            if role == "system":
                continue
            if role == "tool":
                output.append({"role": "user", "content": [{
                    "type": "tool_result", "tool_use_id": str(item.get("tool_call_id", "")),
                    "content": str(item.get("content", "")),
                }]})
                continue
            if role not in {"user", "assistant"}:
                continue
            content: list[dict[str, Any]] = []
            text = item.get("content")
            if isinstance(text, str) and text:
                content.append({"type": "text", "text": text})
            for call in item.get("tool_calls", []) if isinstance(item.get("tool_calls"), list) else []:
                function = call.get("function", {}) if isinstance(call, dict) else {}
                raw = function.get("arguments", "{}") if isinstance(function, dict) else "{}"
                try:
                    args = json.loads(raw) if isinstance(raw, str) else raw
                except (ValueError, TypeError):
                    args = {}
                content.append({
                    "type": "tool_use", "id": str(call.get("id", "")),
                    "name": str(function.get("name", "")), "input": args if isinstance(args, dict) else {},
                })
            output.append({"role": role, "content": content or [{"type": "text", "text": ""}]})
        # Anthropic requires alternating user/assistant messages. Consecutive same-role
        # entries can be safely combined while preserving the block sequence.
        combined: list[dict[str, Any]] = []
        for item in output:
            if combined and combined[-1]["role"] == item["role"]:
                combined[-1]["content"].extend(item["content"])
            else:
                combined.append(item)
        return "\n\n".join(part for part in system_parts if part), combined

    async def chat(
        self, *, api_key_env: str, base_url: str, model_id: str,
        messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None,
        max_output_tokens: int,
    ) -> dict[str, Any]:
        key = await self._credential(api_key_env)
        system, native_messages = self._to_anthropic(messages)
        payload: dict[str, Any] = {"model": model_id, "messages": native_messages, "max_tokens": max_output_tokens}
        if system:
            payload["system"] = system
        if tools:
            native_tools = []
            for item in tools:
                function = item.get("function", {}) if isinstance(item, dict) else {}
                if isinstance(function, dict) and function.get("name"):
                    native_tools.append({
                        "name": function["name"], "description": function.get("description", ""),
                        "input_schema": function.get("parameters", {"type": "object", "properties": {}}),
                    })
            if native_tools:
                payload["tools"] = native_tools
        body = await self._request(
            "POST", f"{self._base(base_url)}/messages",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json", "accept": "application/json"},
            json_body=payload,
        )
        blocks = body.get("content", [])
        if not isinstance(blocks, list):
            raise ProviderError("Anthropic returned an invalid content block list.")
        text_parts: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        for index, block in enumerate(blocks):
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text":
                text_parts.append(str(block.get("text", "")))
            elif block.get("type") == "tool_use":
                tool_calls.append({
                    "id": str(block.get("id", f"tool-{index}")), "type": "function",
                    "function": {"name": str(block.get("name", "")), "arguments": json.dumps(block.get("input", {}), ensure_ascii=False)},
                })
        usage = body.get("usage") if isinstance(body.get("usage"), dict) else {}
        input_tokens = _safe_int(usage.get("input_tokens"))
        output_tokens = _safe_int(usage.get("output_tokens"))
        message: dict[str, Any] = {"role": "assistant", "content": "\n".join(text_parts)}
        if tool_calls:
            message["tool_calls"] = tool_calls
        return {"message": message, "usage": {"prompt_tokens": input_tokens, "completion_tokens": output_tokens, "total_tokens": input_tokens + output_tokens}}

    async def list_models(self, *, api_key_env: str, base_url: str) -> ModelCatalog:
        key = await self._credential(api_key_env)
        body = await self._request(
            "GET", f"{self._base(base_url)}/models?limit=1000",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01", "accept": "application/json"},
        )
        models = body.get("data", [])
        if not isinstance(models, list):
            raise ProviderError("Anthropic model catalog response has an unsupported shape.")
        return ModelCatalog([
            {"id": str(item.get("id", "")), "display_name": str(item.get("display_name", item.get("id", ""))), "capabilities": ["chat"]}
            for item in models if isinstance(item, dict) and item.get("id")
        ], complete=not bool(body.get("has_more", False)))


class GeminiAdapter(_HTTPAdapter):
    @staticmethod
    def _to_gemini(messages: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
        system = "\n\n".join(str(item.get("content", "")) for item in messages if item.get("role") == "system")
        contents: list[dict[str, Any]] = []
        tool_names: dict[str, str] = {}
        for item in messages:
            role = item.get("role")
            if role == "system":
                continue
            if role == "assistant":
                parts: list[dict[str, Any]] = []
                text = item.get("content")
                if isinstance(text, str) and text:
                    parts.append({"text": text})
                for call in item.get("tool_calls", []) if isinstance(item.get("tool_calls"), list) else []:
                    function = call.get("function", {}) if isinstance(call, dict) else {}
                    name = str(function.get("name", "")) if isinstance(function, dict) else ""
                    raw = function.get("arguments", "{}") if isinstance(function, dict) else "{}"
                    try:
                        args = json.loads(raw) if isinstance(raw, str) else raw
                    except (ValueError, TypeError):
                        args = {}
                    call_id = str(call.get("id", ""))
                    tool_names[call_id] = name
                    if name:
                        parts.append({"functionCall": {"name": name, "args": args if isinstance(args, dict) else {}}})
                contents.append({"role": "model", "parts": parts or [{"text": ""}]})
            elif role == "tool":
                call_id = str(item.get("tool_call_id", ""))
                name = tool_names.get(call_id) or str(item.get("name", "nova_tool"))
                contents.append({"role": "user", "parts": [{"functionResponse": {"name": name, "response": {"result": str(item.get("content", ""))}}}]})
            elif role == "user":
                contents.append({"role": "user", "parts": [{"text": str(item.get("content", ""))}]})
        # Merge same-role entries, as required by the provider content format.
        merged: list[dict[str, Any]] = []
        for item in contents:
            if merged and merged[-1]["role"] == item["role"]:
                merged[-1]["parts"].extend(item["parts"])
            else:
                merged.append(item)
        return system, merged

    async def chat(
        self, *, api_key_env: str, base_url: str, model_id: str,
        messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None,
        max_output_tokens: int,
    ) -> dict[str, Any]:
        key = await self._credential(api_key_env)
        system, contents = self._to_gemini(messages)
        model = model_id.removeprefix("models/")
        payload: dict[str, Any] = {"contents": contents, "generationConfig": {"maxOutputTokens": max_output_tokens}}
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}
        declarations = []
        for item in tools or []:
            function = item.get("function", {}) if isinstance(item, dict) else {}
            if isinstance(function, dict) and function.get("name"):
                declarations.append({
                    "name": function["name"], "description": function.get("description", ""),
                    "parameters": function.get("parameters", {"type": "object", "properties": {}}),
                })
        if declarations:
            payload["tools"] = [{"functionDeclarations": declarations}]
        url = f"{self._base(base_url)}/models/{urllib.parse.quote(model, safe='')}:generateContent"
        body = await self._request("POST", url, headers={"x-goog-api-key": key, "content-type": "application/json", "accept": "application/json"}, json_body=payload)
        candidates = body.get("candidates", [])
        if not isinstance(candidates, list) or not candidates:
            raise ProviderError("Gemini returned no candidate response.")
        candidate = candidates[0] if isinstance(candidates[0], dict) else {}
        parts = candidate.get("content", {}).get("parts", []) if isinstance(candidate.get("content"), dict) else []
        text_parts: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        for index, part in enumerate(parts if isinstance(parts, list) else []):
            if not isinstance(part, dict):
                continue
            if isinstance(part.get("text"), str):
                text_parts.append(part["text"])
            call = part.get("functionCall")
            if isinstance(call, dict) and call.get("name"):
                tool_calls.append({
                    "id": f"gemini-call-{index}", "type": "function",
                    "function": {"name": str(call["name"]), "arguments": json.dumps(call.get("args", {}), ensure_ascii=False)},
                })
        usage = body.get("usageMetadata") if isinstance(body.get("usageMetadata"), dict) else {}
        prompt_tokens = _safe_int(usage.get("promptTokenCount"))
        completion_tokens = _safe_int(usage.get("candidatesTokenCount"))
        message: dict[str, Any] = {"role": "assistant", "content": "\n".join(text_parts)}
        if tool_calls:
            message["tool_calls"] = tool_calls
        return {"message": message, "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens, "total_tokens": _safe_int(usage.get("totalTokenCount")) or prompt_tokens + completion_tokens}}

    async def list_models(self, *, api_key_env: str, base_url: str) -> ModelCatalog:
        key = await self._credential(api_key_env)
        body = await self._request("GET", f"{self._base(base_url)}/models?pageSize=1000", headers={"x-goog-api-key": key, "accept": "application/json"})
        models = body.get("models", [])
        if not isinstance(models, list):
            raise ProviderError("Gemini model catalog response has an unsupported shape.")
        result = []
        for item in models:
            if not isinstance(item, dict) or not item.get("name"):
                continue
            methods = item.get("supportedGenerationMethods", [])
            caps = ["chat"] if "generateContent" in methods else []
            # The model list exposes generation support, not per-model function-calling entitlement.
            # Tool capability remains operator-declared and should be enabled only after an eval.
            result.append({"id": str(item["name"]).removeprefix("models/"), "display_name": str(item.get("displayName", item["name"])), "capabilities": caps})
        return ModelCatalog(result, complete=not bool(body.get("nextPageToken")))


_ADAPTERS = {
    "openai": OpenAIAdapter,
    "openai_compatible": OpenAICompatibleAdapter,
    "xai": OpenAICompatibleAdapter,
    "deepseek": OpenAICompatibleAdapter,
    "mistral": OpenAICompatibleAdapter,
    "anthropic": AnthropicAdapter,
    "gemini": GeminiAdapter,
}


def create_adapter(
    provider_type: str, timeout_seconds: int, allow_local_http: bool = False, base_url: str | None = None,
) -> _HTTPAdapter:
    if provider_type == "openai_compatible" and base_url:
        try:
            if (urllib.parse.urlsplit(base_url).hostname or "").lower() == "api.openai.com":
                return OpenAIAdapter(timeout_seconds, allow_local_http)
        except ValueError:
            pass
    adapter = _ADAPTERS.get(provider_type)
    if adapter is None:
        raise ProviderConfigurationError(f"Unsupported provider type: {provider_type}.")
    return adapter(timeout_seconds, allow_local_http)
