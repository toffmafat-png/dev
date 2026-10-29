"""§93 Model Context Protocol (MCP) interoperability and §105 Integration Gateway.

Implements an optional JSON-RPC 2.0 MCP client (``stdio``, ``http`` and an
in-memory loopback transport) alongside a unified integration manager covering
AI providers, MCP connectors, plugins and native tools.

Security & trust boundaries enforced:

* Conversation transcripts and arbitrary local files are never attached to MCP
  requests; only the schema-validated arguments of the invoked tool are sent.
* Every MCP tool output and resource read is marked ``untrusted_external``
  (``provenance='external_source'``) so downstream components never treat it as
  verified host state.
* Consequential MCP calls are checked independently against NOVA's permission
  callback before a request leaves the process.
* Disabling a connector or revoking its credentials immediately clears stored
  auth tokens in memory and returns a clear, actionable unavailable error.
* In the §105 gateway, passing an authentication check proves identity only — it
  never grants permission for operations outside the integration's minimum
  granted scopes.
"""
from __future__ import annotations

import json
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel

from nova.observability import Redactor
from nova.plugins import validate_json_against_schema
from nova.tools.registry import ToolDefinition, ToolOutcome, ToolRegistry

SUPPORTED_MCP_PROTOCOLS = ("2024-11-05", "2025-03-26")
CLIENT_IDENTITY = {"name": "nova-x-desktop", "version": "0.2.0"}

STATUS_CONNECTED = "connected"
STATUS_DISCONNECTED = "disconnected"
STATUS_DISABLED = "disabled"
STATUS_UNAVAILABLE = "unavailable"
STATUS_VERSION_INCOMPATIBLE = "version_incompatible"

TRANSPORT_STDIO = "stdio"
TRANSPORT_HTTP = "http"
TRANSPORT_MEMORY = "memory"


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


class MCPTransportError(RuntimeError):
    """Raised when an MCP transport times out, disconnects or returns malformed JSON-RPC."""


class MCPTransport(Protocol):
    def request(self, method: str, params: dict[str, Any] | None, *, timeout: float) -> dict[str, Any]: ...
    def notify(self, method: str, params: dict[str, Any] | None) -> None: ...
    def close(self) -> None: ...


class InMemoryMCPTransport:
    """Deterministic in-process MCP server simulator for tests and local embedded tools."""

    def __init__(
        self,
        *,
        protocol_version: str = "2024-11-05",
        server_name: str = "mock-mcp",
        server_version: str = "1.0.0",
        tools: list[dict[str, Any]] | None = None,
        resources: list[dict[str, Any]] | None = None,
        call_handler: Callable[[str, dict[str, Any]], Any] | None = None,
    ) -> None:
        self.protocol_version = protocol_version
        self.server_name = server_name
        self.server_version = server_version
        self._tools = list(tools or [])
        self._resources = list(resources or [])
        self._call_handler = call_handler or (lambda name, args: {"echo": args, "tool": name})
        self.closed = False
        self.sent_payloads: list[dict[str, Any]] = []

    def request(self, method: str, params: dict[str, Any] | None, *, timeout: float) -> dict[str, Any]:
        if self.closed:
            raise MCPTransportError("MCP transport is disconnected")
        self.sent_payloads.append({"method": method, "params": params, "timeout": timeout})
        if method == "initialize":
            return {
                "protocolVersion": self.protocol_version,
                "serverInfo": {"name": self.server_name, "version": self.server_version},
                "capabilities": {"tools": {}, "resources": {}},
            }
        if method == "tools/list":
            return {"tools": list(self._tools)}
        if method == "resources/list":
            return {"resources": list(self._resources)}
        if method == "tools/call":
            p = params or {}
            out = self._call_handler(str(p.get("name") or ""), dict(p.get("arguments") or {}))
            return {"content": [{"type": "text", "text": json.dumps(out)}], "isError": False}
        raise MCPTransportError(f"Unsupported MCP method: {method}")

    def notify(self, method: str, params: dict[str, Any] | None) -> None:
        if not self.closed:
            self.sent_payloads.append({"notification": method, "params": params})

    def close(self) -> None:
        self.closed = True


class StdioMCPTransport:
    """Line-delimited JSON-RPC 2.0 over a local child process with scoped environment."""

    def __init__(self, argv: list[str], *, env: dict[str, str] | None = None) -> None:
        if not argv or any("\x00" in item for item in argv):
            raise ValueError("Invalid stdio MCP command")
        safe_env = {"PATH": "/usr/local/bin:/usr/bin:/bin"}
        if env:
            safe_env.update(env)
        self._proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=safe_env,
        )
        self._req_id = 0

    def request(self, method: str, params: dict[str, Any] | None, *, timeout: float) -> dict[str, Any]:
        if self._proc.poll() is not None or self._proc.stdin is None or self._proc.stdout is None:
            raise MCPTransportError("stdio MCP process is not running")
        self._req_id += 1
        envelope = {"jsonrpc": "2.0", "id": self._req_id, "method": method, "params": params or {}}
        try:
            self._proc.stdin.write(json.dumps(envelope) + "\n")
            self._proc.stdin.flush()
            import selectors

            sel = selectors.DefaultSelector()
            try:
                sel.register(self._proc.stdout, selectors.EVENT_READ)
                ready = sel.select(timeout=max(0.1, timeout))
                if not ready:
                    raise MCPTransportError(f"stdio MCP request '{method}' timed out after {timeout:g}s")
                line = self._proc.stdout.readline()
            finally:
                sel.close()
        except OSError as exc:
            raise MCPTransportError(f"stdio MCP I/O failure: {exc}") from exc
        if not line:
            raise MCPTransportError("stdio MCP server closed stdout")
        try:
            decoded = json.loads(line)
        except ValueError as exc:
            raise MCPTransportError("stdio MCP response was not valid JSON") from exc
        if "error" in decoded:
            raise MCPTransportError(f"MCP error: {decoded['error']}")
        result = decoded.get("result")
        if not isinstance(result, dict):
            raise MCPTransportError("MCP result must be a JSON object")
        return result

    def notify(self, method: str, params: dict[str, Any] | None) -> None:
        if self._proc.poll() is None and self._proc.stdin is not None:
            try:
                self._proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method, "params": params or {}}) + "\n")
                self._proc.stdin.flush()
            except OSError:
                pass

    def close(self) -> None:
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._proc.kill()


class HttpMCPTransport:
    """HTTPS JSON-RPC 2.0 MCP transport with revocable Bearer authentication."""

    def __init__(self, endpoint: str, *, bearer_token: str = "", allow_local_http: bool = False) -> None:
        parsed = urlparse(endpoint)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            raise ValueError(f"Invalid MCP HTTP endpoint: {endpoint!r}")
        if parsed.scheme == "http" and not (allow_local_http and parsed.hostname in {"127.0.0.1", "localhost"}):
            raise ValueError("Remote MCP HTTP endpoints must use HTTPS")
        self.endpoint = endpoint
        self._token = bearer_token
        self._req_id = 0
        self._closed = False

    def clear_credentials(self) -> None:
        self._token = ""

    def request(self, method: str, params: dict[str, Any] | None, *, timeout: float) -> dict[str, Any]:
        if self._closed:
            raise MCPTransportError("HTTP MCP transport is closed")
        self._req_id += 1
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        envelope = {"jsonrpc": "2.0", "id": self._req_id, "method": method, "params": params or {}}
        try:
            response = httpx.post(self.endpoint, json=envelope, headers=headers, timeout=max(0.5, timeout))
            response.raise_for_status()
            decoded = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise MCPTransportError(f"HTTP MCP transport failed: {type(exc).__name__}") from exc
        if "error" in decoded:
            raise MCPTransportError(f"MCP error: {decoded['error']}")
        result = decoded.get("result")
        if not isinstance(result, dict):
            raise MCPTransportError("MCP result must be a JSON object")
        return result

    def notify(self, method: str, params: dict[str, Any] | None) -> None:
        return None

    def close(self) -> None:
        self._closed = True
        self._token = ""


@dataclass
class MCPServerConfig:
    server_id: str
    transport: str
    endpoint_or_cmd: str | list[str]
    timeout_seconds: float = 10.0
    granted_scopes: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    consequential_tools: tuple[str, ...] = ()
    bearer_token: str = ""
    allow_local_http: bool = False


@dataclass
class MCPConnectorState:
    config: MCPServerConfig
    status: str = STATUS_DISCONNECTED
    protocol_version: str = ""
    server_identity: dict[str, Any] = field(default_factory=dict)
    capabilities: dict[str, Any] = field(default_factory=dict)
    tools: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    last_error: str = ""
    credentials_configured: bool = False
    connected_at: str = ""
    _transport: MCPTransport | None = field(default=None, repr=False)

    def public_summary(self) -> dict[str, Any]:
        return {
            "server_id": self.config.server_id,
            "transport": self.config.transport,
            "status": self.status,
            "protocol_version": self.protocol_version,
            "server_identity": dict(self.server_identity),
            "capabilities": dict(self.capabilities),
            "granted_scopes": list(self.config.granted_scopes),
            "allowed_tools": list(self.config.allowed_tools),
            "available_tools": [
                {"name": t.get("name", ""), "description": t.get("description", ""), "inputSchema": t.get("inputSchema", {})}
                for t in self.tools
            ],
            "available_resources": [
                {"uri": r.get("uri", ""), "name": r.get("name", "")}
                for r in self.resources
            ],
            "credentials_configured": self.credentials_configured,
            "last_error": self.last_error,
            "connected_at": self.connected_at,
        }


@dataclass
class MCPClientManager:
    """§93 Optional MCP client manager coexisting with native NOVA tools."""

    permission_check: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None
    redactor: Redactor = field(default_factory=Redactor)
    _servers: dict[str, MCPConnectorState] = field(default_factory=dict, init=False)

    def register_server(self, config: MCPServerConfig, *, transport_override: MCPTransport | None = None) -> dict[str, Any]:
        if not config.server_id or not config.server_id.replace("-", "").replace("_", "").isalnum():
            raise ValueError(f"Invalid MCP server_id: {config.server_id!r}")
        if config.bearer_token:
            self.redactor.register_secret(config.bearer_token)
        state = MCPConnectorState(
            config=config,
            status=STATUS_DISCONNECTED,
            credentials_configured=bool(config.bearer_token),
            _transport=transport_override,
        )
        self._servers[config.server_id] = state
        return state.public_summary()

    def _ensure_transport(self, state: MCPConnectorState) -> MCPTransport:
        if state._transport is not None:
            return state._transport
        cfg = state.config
        if cfg.transport == TRANSPORT_STDIO:
            if not isinstance(cfg.endpoint_or_cmd, list):
                raise ValueError("stdio MCP server requires command argv list")
            state._transport = StdioMCPTransport(cfg.endpoint_or_cmd)
            return state._transport
        if cfg.transport == TRANSPORT_HTTP:
            if not isinstance(cfg.endpoint_or_cmd, str):
                raise ValueError("http MCP server requires endpoint URL string")
            state._transport = HttpMCPTransport(
                cfg.endpoint_or_cmd,
                bearer_token=cfg.bearer_token,
                allow_local_http=cfg.allow_local_http,
            )
            return state._transport
        raise ValueError(f"Unsupported MCP transport '{cfg.transport}'")

    def connect(self, server_id: str) -> dict[str, Any]:
        state = self._servers.get(server_id)
        if state is None:
            return {"connected": False, "status": STATUS_UNAVAILABLE, "error": f"MCP server '{server_id}' is not registered"}
        if state.status == STATUS_DISABLED:
            return {"connected": False, "status": STATUS_DISABLED, "error": f"MCP server '{server_id}' is disabled"}
        try:
            transport = self._ensure_transport(state)
            init_res = transport.request(
                "initialize",
                {
                    "protocolVersion": SUPPORTED_MCP_PROTOCOLS[-1],
                    "clientInfo": CLIENT_IDENTITY,
                    "capabilities": {},
                },
                timeout=state.config.timeout_seconds,
            )
        except (MCPTransportError, ValueError, OSError) as exc:
            state.status = STATUS_UNAVAILABLE
            state.last_error = self.redactor.scrub_text(str(exc), max_chars=240)
            return {"connected": False, "status": state.status, "error": state.last_error}

        negotiated = str(init_res.get("protocolVersion") or "")
        if negotiated not in SUPPORTED_MCP_PROTOCOLS:
            state.status = STATUS_VERSION_INCOMPATIBLE
            state.protocol_version = negotiated
            state.last_error = (
                f"server protocol '{negotiated}' is incompatible with supported versions {SUPPORTED_MCP_PROTOCOLS}"
            )
            transport.close()
            return {"connected": False, "status": state.status, "error": state.last_error}

        transport.notify("notifications/initialized", {})
        state.protocol_version = negotiated
        state.server_identity = dict(init_res.get("serverInfo") or {})
        state.capabilities = dict(init_res.get("capabilities") or {})
        try:
            tools_res = transport.request("tools/list", {}, timeout=state.config.timeout_seconds)
            raw_tools = [t for t in (tools_res.get("tools") or []) if isinstance(t, dict)]
            if state.config.allowed_tools:
                allowed = set(state.config.allowed_tools)
                raw_tools = [t for t in raw_tools if t.get("name") in allowed]
            state.tools = raw_tools
        except MCPTransportError:
            state.tools = []

        try:
            res_list = transport.request("resources/list", {}, timeout=state.config.timeout_seconds)
            state.resources = [r for r in (res_list.get("resources") or []) if isinstance(r, dict)]
        except MCPTransportError:
            state.resources = []

        state.status = STATUS_CONNECTED
        state.last_error = ""
        state.connected_at = _iso()
        return {"connected": True, **state.public_summary()}

    def disconnect(self, server_id: str) -> dict[str, Any]:
        state = self._servers.get(server_id)
        if state is None:
            return {"disconnected": False, "error": f"MCP server '{server_id}' is not registered"}
        if state._transport is not None:
            state._transport.close()
        state.status = STATUS_DISCONNECTED
        return {"disconnected": True, "server_id": server_id, "status": state.status}

    def disable_and_revoke(self, server_id: str) -> dict[str, Any]:
        """Disable an MCP connector and wipe its configured credentials (§93)."""
        state = self._servers.get(server_id)
        if state is None:
            return {"disabled": False, "error": f"MCP server '{server_id}' is not registered"}
        if state._transport is not None:
            if isinstance(state._transport, HttpMCPTransport):
                state._transport.clear_credentials()
            state._transport.close()
        state.config.bearer_token = ""
        state.credentials_configured = False
        state.status = STATUS_DISABLED
        state.tools = []
        state.resources = []
        return {"disabled": True, "credentials_revoked": True, "server_id": server_id, "status": state.status}

    def call_tool(self, server_id: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Invoke a discovered MCP tool with schema validation, policy gate and untrusted tagging."""
        state = self._servers.get(server_id)
        if state is None:
            return {
                "status": "error",
                "error": f"MCP integration '{server_id}' is not registered. Configure it in the integration manager first.",
            }
        if state.status != STATUS_CONNECTED or state._transport is None:
            return {
                "status": "error",
                "server_id": server_id,
                "connector_status": state.status,
                "error": (
                    f"MCP integration '{server_id}' is currently {state.status}"
                    + (f" ({state.last_error})" if state.last_error else "")
                    + "; reconnect or inspect server health before calling its tools."
                ),
            }
        spec = next((item for item in state.tools if item.get("name") == tool_name), None)
        if spec is None:
            return {"status": "denied", "error": f"tool '{tool_name}' is not available or not permitted on '{server_id}'"}

        schema = spec.get("inputSchema")
        if isinstance(schema, dict) and schema.get("type") == "object":
            issues = validate_json_against_schema(arguments, schema)
            if issues:
                return {"status": "error", "error": "invalid MCP tool arguments: " + "; ".join(issues)}

        # Independent permission check before executing consequential operations (§93).
        qualified_name = f"mcp.{server_id}.{tool_name}"
        is_consequential = (not state.config.consequential_tools) or (tool_name in state.config.consequential_tools)
        if is_consequential and self.permission_check is not None:
            decision = self.permission_check(qualified_name, arguments)
            if decision.get("action") != "allow":
                return {
                    "status": "denied",
                    "error": f"autonomy policy blocked '{qualified_name}': {decision.get('reason', '')}",
                }

        # §93: Only the minimal validated arguments are sent — never conversation history or local files.
        sanitized_args = {
            k: v
            for k, v in arguments.items()
            if k not in {"_conversation_history", "_local_files", "_system_prompt"}
        }
        try:
            raw_result = state._transport.request(
                "tools/call",
                {"name": tool_name, "arguments": sanitized_args},
                timeout=state.config.timeout_seconds,
            )
        except MCPTransportError as exc:
            state.status = STATUS_UNAVAILABLE
            state.last_error = self.redactor.scrub_text(str(exc), max_chars=240)
            return {
                "status": "error",
                "connector_status": state.status,
                "error": f"MCP call to '{qualified_name}' failed: {state.last_error}",
            }

        return {
            "status": "success",
            "server_id": server_id,
            "tool": tool_name,
            "trust_level": "untrusted_external",
            "provenance": "external_source",
            "conversation_forwarded": False,
            "local_files_forwarded": False,
            "content": self.redactor.scrub(raw_result.get("content", []), max_chars=2_000),
            "is_error": bool(raw_result.get("isError", False)),
        }

    def bind_into_tool_registry(self, server_id: str, registry: ToolRegistry) -> list[str]:
        state = self._servers.get(server_id)
        if state is None or state.status != STATUS_CONNECTED:
            return []
        bound: list[str] = []
        for spec in state.tools:
            tname = str(spec.get("name") or "")
            if not tname:
                continue
            qualified = f"mcp.{server_id}.{tname}"
            if registry.get(qualified) is not None:
                continue

            class _MCPArgs(BaseModel):
                model_config = {"extra": "allow"}

            def _make_handler(sid: str, name: str):
                async def _handler(parsed: BaseModel, _approved: bool) -> ToolOutcome:
                    res = self.call_tool(sid, name, parsed.model_dump())
                    if res["status"] == "success":
                        return ToolOutcome("success", f"MCP '{sid}.{name}' returned untrusted external output.", res)
                    return ToolOutcome(res["status"], res.get("error", "MCP tool error"), res)

                return _handler

            schema = spec.get("inputSchema")
            if not isinstance(schema, dict) or schema.get("type") != "object":
                schema = {"type": "object", "properties": {}}
            registry.register(
                ToolDefinition(
                    name=qualified,
                    description=f"[MCP:{server_id}] {spec.get('description', tname)}",
                    parameters=schema,
                    input_model=_MCPArgs,
                    handler=_make_handler(server_id, tname),
                    permission=f"mcp.{server_id}",
                    available=True,
                    category="mcp",
                    autonomy_class="approval_required",
                )
            )
            bound.append(qualified)
        return bound

    def list_servers(self) -> list[dict[str, Any]]:
        return [item.public_summary() for item in self._servers.values()]


# ----------------------------------------- §105 API Gateway & Integration Manager


@dataclass
class IntegrationRecord:
    integration_id: str
    kind: str  # ai_provider | mcp_server | plugin | local_tool | external_service
    label: str
    capabilities: tuple[str, ...]
    supported_operations: dict[str, str]  # operation -> required_scope
    minimum_scopes: tuple[str, ...]
    granted_scopes: tuple[str, ...] = ()
    timeout_seconds: float = 30.0
    rate_limit_per_minute: int = 60
    fallback_ids: tuple[str, ...] = ()
    enabled: bool = True
    credentials_present: bool = True
    auth_verified: bool = False
    status: str = "healthy"
    unavailable_reason: str = ""
    health_probe: Callable[[], tuple[bool, str]] | None = None
    _call_timestamps: list[float] = field(default_factory=list, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "kind": self.kind,
            "label": self.label,
            "enabled": self.enabled,
            "status": self.status,
            "unavailable_reason": self.unavailable_reason,
            "capabilities": list(self.capabilities),
            "supported_operations": dict(self.supported_operations),
            "minimum_scopes": list(self.minimum_scopes),
            "granted_scopes": list(self.granted_scopes),
            "credentials_present": self.credentials_present,
            "auth_verified": self.auth_verified,
            "timeout_seconds": self.timeout_seconds,
            "rate_limit_per_minute": self.rate_limit_per_minute,
            "fallback_ids": list(self.fallback_ids),
        }


@dataclass
class IntegrationGateway:
    """§105 Consistent integration manager with health, minimum scopes, rate limits & fallbacks."""

    redactor: Redactor = field(default_factory=Redactor)
    _records: dict[str, IntegrationRecord] = field(default_factory=dict, init=False)

    def register(self, record: IntegrationRecord) -> dict[str, Any]:
        if not record.credentials_present:
            record.status = "unavailable"
            record.unavailable_reason = "missing required credentials"
        elif not record.enabled:
            record.status = "disabled"
            record.unavailable_reason = "disabled by operator"
        self._records[record.integration_id] = record
        return record.to_dict()

    def disable(self, integration_id: str) -> bool:
        rec = self._records.get(integration_id)
        if rec is None:
            return False
        rec.enabled = False
        rec.status = "disabled"
        rec.unavailable_reason = "disabled by operator"
        return True

    def revoke_access(self, integration_id: str) -> dict[str, Any]:
        rec = self._records.get(integration_id)
        if rec is None:
            return {"revoked": False, "reason": f"integration '{integration_id}' not found"}
        rec.enabled = False
        rec.credentials_present = False
        rec.auth_verified = False
        rec.granted_scopes = ()
        rec.status = "unavailable"
        rec.unavailable_reason = "credentials and scopes revoked by operator"
        return {"revoked": True, "integration": rec.to_dict()}

    def record_auth_test(self, integration_id: str, passed: bool, detail: str = "") -> dict[str, Any]:
        """Record an authentication test without expanding granted operation scopes (§105)."""
        rec = self._records.get(integration_id)
        if rec is None:
            return {"ok": False, "reason": f"integration '{integration_id}' not found"}
        rec.auth_verified = bool(passed)
        if not passed:
            rec.status = "unavailable"
            rec.unavailable_reason = self.redactor.scrub_text(detail or "authentication test failed", max_chars=200)
        elif rec.enabled and rec.credentials_present:
            rec.status = "healthy"
            rec.unavailable_reason = ""
        return {
            "integration_id": integration_id,
            "auth_verified": rec.auth_verified,
            "granted_scopes": list(rec.granted_scopes),
            "note": "Authentication confirms identity only; operations still require their specific minimum scope.",
        }

    def check_operation(self, integration_id: str, operation: str, *, consume_rate_limit: bool = True) -> dict[str, Any]:
        """Verify availability, rate limits AND minimum per-operation scope (§105)."""
        rec = self._records.get(integration_id)
        if rec is None:
            return {"allowed": False, "reason": f"integration '{integration_id}' is not registered"}
        if not rec.enabled:
            return {"allowed": False, "reason": f"integration '{integration_id}' is disabled", "fallbacks": self._healthy_fallbacks(rec)}
        if not rec.credentials_present:
            return {
                "allowed": False,
                "reason": f"integration '{integration_id}' is missing required credentials",
                "fallbacks": self._healthy_fallbacks(rec),
            }
        if rec.status in {"unavailable", "error"}:
            return {
                "allowed": False,
                "reason": f"integration '{integration_id}' is unavailable: {rec.unavailable_reason}",
                "fallbacks": self._healthy_fallbacks(rec),
            }
        required_scope = rec.supported_operations.get(operation)
        if required_scope is None:
            return {"allowed": False, "reason": f"operation '{operation}' is not supported by '{integration_id}'"}
        if required_scope and required_scope not in rec.granted_scopes:
            # §105: Even if auth_verified is True, ungranted operation scopes are refused.
            return {
                "allowed": False,
                "auth_verified": rec.auth_verified,
                "reason": f"operation '{operation}' requires scope '{required_scope}', which is not in granted_scopes",
            }
        now = time.monotonic()
        rec._call_timestamps = [t for t in rec._call_timestamps if now - t < 60.0]
        if len(rec._call_timestamps) >= rec.rate_limit_per_minute:
            return {
                "allowed": False,
                "rate_limited": True,
                "reason": f"rate limit ({rec.rate_limit_per_minute}/min) exceeded for '{integration_id}'",
                "fallbacks": self._healthy_fallbacks(rec),
            }
        if consume_rate_limit:
            rec._call_timestamps.append(now)
        return {"allowed": True, "integration_id": integration_id, "operation": operation, "scope": required_scope}

    def _healthy_fallbacks(self, rec: IntegrationRecord) -> list[str]:
        out: list[str] = []
        for fid in rec.fallback_ids:
            cand = self._records.get(fid)
            if cand and cand.enabled and cand.credentials_present and cand.status == "healthy":
                out.append(fid)
        return out

    def run_health_checks(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for rec in self._records.values():
            if not rec.enabled or not rec.credentials_present:
                results.append(rec.to_dict())
                continue
            if rec.health_probe is not None:
                try:
                    ok, detail = rec.health_probe()
                except Exception as exc:
                    ok, detail = False, f"{type(exc).__name__}: {exc}"
                rec.status = "healthy" if ok else "unavailable"
                rec.unavailable_reason = "" if ok else self.redactor.scrub_text(detail, max_chars=200)
            results.append(rec.to_dict())
        return results

    def list_integrations(self) -> list[dict[str, Any]]:
        return [rec.to_dict() for rec in self._records.values()]


__all__ = [
    "CLIENT_IDENTITY",
    "STATUS_CONNECTED",
    "STATUS_DISABLED",
    "STATUS_DISCONNECTED",
    "STATUS_UNAVAILABLE",
    "STATUS_VERSION_INCOMPATIBLE",
    "SUPPORTED_MCP_PROTOCOLS",
    "TRANSPORT_HTTP",
    "TRANSPORT_MEMORY",
    "TRANSPORT_STDIO",
    "HttpMCPTransport",
    "InMemoryMCPTransport",
    "IntegrationGateway",
    "IntegrationRecord",
    "MCPClientManager",
    "MCPConnectorState",
    "MCPServerConfig",
    "MCPTransport",
    "MCPTransportError",
    "StdioMCPTransport",
]
