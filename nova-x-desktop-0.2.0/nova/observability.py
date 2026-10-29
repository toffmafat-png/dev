"""§103 Observability and debugging, with default-on secret redaction.

Provides correlated spans across model calls, tool invocations, workflow steps,
sandbox runs and verification checks so an operator can answer the concrete
questions §103 lists without scraping raw transcripts:

* Which model was called?
* Which tools were invoked?
* Which step failed?
* How many retries occurred?
* How long did an operation take?
* Which cost information is available?
* What result was returned?
* Which verification check passed or failed?

Privacy rules enforced here:

* Configured secret values and common credential patterns (Bearer tokens, API
  keys, URL userinfo, password/token assignments) are redacted before anything
  is stored or exported.
* Attribute values are length-capped so full private conversations, files or
  screenshots are never retained inside traces.
* Telemetry is local by default. External export is disabled unless the
  operator explicitly supplies an endpoint and opts in.
"""
from __future__ import annotations

import re
import secrets
import time
from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

TRACE_SCHEMA_VERSION = "nova-trace-v1"

SPAN_MODEL_CALL = "model_call"
SPAN_TOOL_CALL = "tool_call"
SPAN_VERIFICATION = "verification"
SPAN_WORKFLOW_STEP = "workflow_step"
SPAN_SANDBOX_RUN = "sandbox_run"
SPAN_MCP_CALL = "mcp_call"
SPAN_TASK = "task"
SPAN_KINDS = (
    SPAN_TASK,
    SPAN_MODEL_CALL,
    SPAN_TOOL_CALL,
    SPAN_VERIFICATION,
    SPAN_WORKFLOW_STEP,
    SPAN_SANDBOX_RUN,
    SPAN_MCP_CALL,
)

STATUS_OK = "ok"
STATUS_ERROR = "error"
STATUS_DENIED = "denied"
STATUS_CANCELLED = "cancelled"
STATUS_TIMEOUT = "timeout"

REDACTED = "[REDACTED]"
MAX_SUMMARY_CHARS = 400
MAX_ATTR_CHARS = 300
DEFAULT_MAX_SPANS = 2_000
DEFAULT_RETENTION_HOURS = 72.0

# Patterns that look like credentials even when the caller forgot to register
# the literal secret string.
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-+/=]{8,}"), r"\1 " + REDACTED),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{12,}\b"), REDACTED),
    (re.compile(r"\btvly-[A-Za-z0-9_\-]{10,}\b"), REDACTED),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"), REDACTED),
    (re.compile(r"\bAKIA[0-9A-Z]{12,}\b"), REDACTED),
    (re.compile(r"(https?://)([^/\s:@]+):([^/\s@]+)@"), r"\1" + REDACTED + ":" + REDACTED + "@"),
    (
        re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|secret|password|passwd|authorization)\s*([=:])\s*([^\s,;\"']+)"),
        r"\1\2" + REDACTED,
    ),
)

_SENSITIVE_FIELD_NAMES = frozenset(
    {
        "api_key",
        "apikey",
        "ai_api_key",
        "access_token",
        "nova_access_token",
        "tavily_api_key",
        "token",
        "secret",
        "password",
        "passwd",
        "authorization",
        "cookie",
        "set-cookie",
        "credentials",
        "private_key",
    }
)


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(moment: datetime | None = None) -> str:
    return (moment or _now()).isoformat(timespec="microseconds")


def new_trace_id() -> str:
    """16-byte / 32-hex identifier compatible with W3C Trace Context / OpenTelemetry."""
    return secrets.token_hex(16)


def new_span_id() -> str:
    """8-byte / 16-hex span identifier compatible with OpenTelemetry."""
    return secrets.token_hex(8)


@dataclass
class Redactor:
    """Scrubs literal secrets and common credential patterns from text and structures."""

    literal_secrets: tuple[str, ...] = ()
    max_field_chars: int = MAX_ATTR_CHARS
    _secrets: list[str] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        self._secrets = []
        for item in self.literal_secrets:
            self.register_secret(item)

    def register_secret(self, secret: str) -> None:
        cleaned = (secret or "").strip()
        # Very short strings (e.g. "1" or "ok") would corrupt ordinary output.
        if len(cleaned) >= 6 and cleaned not in self._secrets:
            self._secrets.append(cleaned)
            self._secrets.sort(key=len, reverse=True)

    def scrub_text(self, value: str, *, max_chars: int | None = None) -> str:
        text = str(value or "")
        for secret in self._secrets:
            if secret in text:
                text = text.replace(secret, REDACTED)
        for pattern, replacement in _SECRET_PATTERNS:
            text = pattern.sub(replacement, text)
        cap = self.max_field_chars if max_chars is None else max_chars
        if cap > 0 and len(text) > cap:
            return text[:cap] + "…[truncated]"
        return text

    def scrub(self, value: Any, *, max_chars: int | None = None, _depth: int = 0) -> Any:
        if _depth > 6:
            return "[max-depth]"
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            return self.scrub_text(value, max_chars=max_chars)
        if isinstance(value, bytes):
            return f"[{len(value)} bytes omitted]"
        if isinstance(value, Mapping):
            cleaned: dict[str, Any] = {}
            for raw_key, item in list(value.items())[:60]:
                key = str(raw_key)
                if key.lower().strip() in _SENSITIVE_FIELD_NAMES:
                    cleaned[key] = REDACTED if item else ""
                else:
                    cleaned[key] = self.scrub(item, max_chars=max_chars, _depth=_depth + 1)
            return cleaned
        if isinstance(value, Iterable):
            return [self.scrub(item, max_chars=max_chars, _depth=_depth + 1) for item in list(value)[:60]]
        return self.scrub_text(repr(value), max_chars=max_chars)


@dataclass
class Span:
    """One structured, redacted observation of an operation."""

    trace_id: str
    span_id: str
    name: str
    kind: str
    started_at: str
    ended_at: str = ""
    parent_span_id: str = ""
    task_id: str = ""
    step_index: int | None = None
    model: str = ""
    tool_name: str = ""
    status: str = STATUS_OK
    exit_code: int | None = None
    error_category: str = ""
    retries: int = 0
    duration_ms: float = 0.0
    cost_usd: float | None = None
    verification_status: str = ""
    result_summary: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "name": self.name,
            "kind": self.kind,
            "task_id": self.task_id,
            "step_index": self.step_index,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_ms": self.duration_ms,
            "model": self.model,
            "tool_name": self.tool_name,
            "status": self.status,
            "exit_code": self.exit_code,
            "error_category": self.error_category,
            "retries": self.retries,
            "cost_usd": self.cost_usd,
            "verification_status": self.verification_status,
            "result_summary": self.result_summary,
            "attributes": dict(self.attributes),
        }

    def to_otel_dict(self) -> dict[str, Any]:
        """OpenTelemetry-shaped span representation for explicit opt-in export."""
        attrs = dict(self.attributes)
        if self.task_id:
            attrs["nova.task_id"] = self.task_id
        if self.model:
            attrs["gen_ai.request.model"] = self.model
        if self.tool_name:
            attrs["nova.tool.name"] = self.tool_name
        if self.exit_code is not None:
            attrs["process.exit_code"] = self.exit_code
        if self.error_category:
            attrs["error.type"] = self.error_category
        if self.retries:
            attrs["nova.retries"] = self.retries
        if self.cost_usd is not None:
            attrs["nova.cost_usd"] = self.cost_usd
        if self.verification_status:
            attrs["nova.verification.status"] = self.verification_status
        return {
            "traceId": self.trace_id,
            "spanId": self.span_id,
            "parentSpanId": self.parent_span_id,
            "name": self.name,
            "kind": self.kind,
            "startTime": self.started_at,
            "endTime": self.ended_at,
            "durationMs": self.duration_ms,
            "status": {"code": "OK" if self.status == STATUS_OK else "ERROR", "status": self.status},
            "attributes": attrs,
        }


@dataclass
class TraceCollector:
    """Local-by-default span store with redaction, retention and task Q&A."""

    redactor: Redactor = field(default_factory=Redactor)
    max_spans: int = DEFAULT_MAX_SPANS
    retention_hours: float = DEFAULT_RETENTION_HOURS
    external_export_enabled: bool = False
    external_endpoint: str = ""
    _spans: list[Span] = field(default_factory=list, init=False)
    _task_traces: dict[str, str] = field(default_factory=dict, init=False)

    def trace_id_for_task(self, task_id: str) -> str:
        if not task_id:
            return new_trace_id()
        existing = self._task_traces.get(task_id)
        if existing:
            return existing
        created = new_trace_id()
        self._task_traces[task_id] = created
        return created

    def record(
        self,
        *,
        name: str,
        kind: str,
        task_id: str = "",
        trace_id: str = "",
        parent_span_id: str = "",
        step_index: int | None = None,
        model: str = "",
        tool_name: str = "",
        status: str = STATUS_OK,
        exit_code: int | None = None,
        error_category: str = "",
        retries: int = 0,
        duration_ms: float = 0.0,
        cost_usd: float | None = None,
        verification_status: str = "",
        result_summary: str = "",
        attributes: Mapping[str, Any] | None = None,
        started_at: str = "",
        ended_at: str = "",
    ) -> Span:
        if kind not in SPAN_KINDS:
            raise ValueError(f"Unknown span kind: {kind}")
        resolved_trace = trace_id or self.trace_id_for_task(task_id)
        now_iso = _iso()
        span = Span(
            trace_id=resolved_trace,
            span_id=new_span_id(),
            parent_span_id=parent_span_id,
            name=self.redactor.scrub_text(name, max_chars=120),
            kind=kind,
            task_id=task_id,
            step_index=step_index,
            started_at=started_at or now_iso,
            ended_at=ended_at or now_iso,
            model=self.redactor.scrub_text(model, max_chars=120),
            tool_name=self.redactor.scrub_text(tool_name, max_chars=120),
            status=status,
            exit_code=exit_code,
            error_category=self.redactor.scrub_text(error_category, max_chars=80),
            retries=max(0, int(retries)),
            duration_ms=round(max(0.0, float(duration_ms)), 3),
            cost_usd=(round(float(cost_usd), 6) if cost_usd is not None else None),
            verification_status=self.redactor.scrub_text(verification_status, max_chars=40),
            result_summary=self.redactor.scrub_text(result_summary, max_chars=MAX_SUMMARY_CHARS),
            attributes=self.redactor.scrub(dict(attributes or {})) if attributes else {},
        )
        self._spans.append(span)
        self.apply_retention()
        return span

    @contextmanager
    def start_span(
        self,
        name: str,
        *,
        kind: str,
        task_id: str = "",
        trace_id: str = "",
        parent_span_id: str = "",
        step_index: int | None = None,
        model: str = "",
        tool_name: str = "",
        attributes: Mapping[str, Any] | None = None,
    ):
        """Time an operation and record its redacted span on exit."""
        started_wall = _iso()
        started_mono = time.monotonic()
        holder: dict[str, Any] = {
            "status": STATUS_OK,
            "exit_code": None,
            "error_category": "",
            "retries": 0,
            "cost_usd": None,
            "verification_status": "",
            "result_summary": "",
            "attributes": dict(attributes or {}),
        }
        try:
            yield holder
        except Exception as exc:
            holder["status"] = STATUS_ERROR
            holder["error_category"] = type(exc).__name__
            holder["result_summary"] = str(exc)
            raise
        finally:
            elapsed = (time.monotonic() - started_mono) * 1000.0
            self.record(
                name=name,
                kind=kind,
                task_id=task_id,
                trace_id=trace_id,
                parent_span_id=parent_span_id,
                step_index=step_index,
                model=holder.get("model") or model,
                tool_name=holder.get("tool_name") or tool_name,
                status=str(holder.get("status") or STATUS_OK),
                exit_code=holder.get("exit_code"),
                error_category=str(holder.get("error_category") or ""),
                retries=int(holder.get("retries") or 0),
                duration_ms=elapsed,
                cost_usd=holder.get("cost_usd"),
                verification_status=str(holder.get("verification_status") or ""),
                result_summary=str(holder.get("result_summary") or ""),
                attributes=holder.get("attributes") or {},
                started_at=started_wall,
                ended_at=_iso(),
            )

    def apply_retention(self, *, now: datetime | None = None) -> int:
        reference = now or _now()
        cutoff = reference - timedelta(hours=max(0.01, float(self.retention_hours)))
        before = len(self._spans)
        kept: list[Span] = []
        for item in self._spans:
            try:
                ended = datetime.fromisoformat(item.ended_at or item.started_at)
                if ended.tzinfo is None:
                    ended = ended.replace(tzinfo=UTC)
                if ended < cutoff:
                    continue
            except ValueError:
                pass
            kept.append(item)
        if len(kept) > self.max_spans:
            kept = kept[-self.max_spans :]
        self._spans = kept
        return before - len(kept)

    def list_spans(
        self,
        *,
        task_id: str = "",
        trace_id: str = "",
        kind: str = "",
        status: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        rows = self._spans
        if task_id:
            rows = [item for item in rows if item.task_id == task_id]
        if trace_id:
            rows = [item for item in rows if item.trace_id == trace_id]
        if kind:
            rows = [item for item in rows if item.kind == kind]
        if status:
            rows = [item for item in rows if item.status == status]
        cap = max(1, min(int(limit), self.max_spans))
        return [item.to_dict() for item in rows[-cap:]]

    def explain_task(self, task_id: str) -> dict[str, Any]:
        """Answer all eight §103 diagnostic questions for ``task_id``."""
        spans = [item for item in self._spans if item.task_id == task_id]
        models = sorted({item.model for item in spans if item.model})
        tools = [item.tool_name for item in spans if item.tool_name]
        failed = [
            {
                "span_id": item.span_id,
                "name": item.name,
                "kind": item.kind,
                "step_index": item.step_index,
                "status": item.status,
                "exit_code": item.exit_code,
                "error_category": item.error_category,
                "summary": item.result_summary,
            }
            for item in spans
            if item.status != STATUS_OK
        ]
        known_costs = [item.cost_usd for item in spans if item.cost_usd is not None]
        verifications = [
            {
                "span_id": item.span_id,
                "verification_status": item.verification_status or item.status,
                "summary": item.result_summary,
            }
            for item in spans
            if item.kind == SPAN_VERIFICATION or item.verification_status
        ]
        return {
            "task_id": task_id,
            "trace_id": self._task_traces.get(task_id, ""),
            "span_count": len(spans),
            "models_called": models,
            "tools_invoked": tools,
            "failed_steps": failed,
            "total_retries": sum(item.retries for item in spans),
            "total_duration_ms": round(sum(item.duration_ms for item in spans), 3),
            "cost": {
                "available": bool(known_costs),
                "total_usd": round(sum(known_costs), 6) if known_costs else None,
                "priced_spans": len(known_costs),
                "unpriced_spans": len(spans) - len(known_costs),
            },
            "results_returned": [
                {"name": item.name, "kind": item.kind, "status": item.status, "summary": item.result_summary}
                for item in spans
                if item.result_summary
            ],
            "verification_checks": verifications,
        }

    def export_otel_payload(self, *, task_id: str = "") -> dict[str, Any]:
        """Prepare an OpenTelemetry-shaped JSON payload; refuses implicit remote export."""
        spans = [item for item in self._spans if not task_id or item.task_id == task_id]
        return {
            "schema_version": TRACE_SCHEMA_VERSION,
            "local_by_default": True,
            "external_export_enabled": bool(self.external_export_enabled and self.external_endpoint),
            "external_endpoint": self.external_endpoint if self.external_export_enabled else "",
            "resource": {"service.name": "nova-x-desktop"},
            "spans": [item.to_otel_dict() for item in spans],
            "note": (
                "Telemetry stays local unless external_export_enabled is True and an explicit "
                "endpoint is configured. All span fields pass through secret redaction first."
            ),
        }

    def clear(self, *, task_id: str = "") -> int:
        if not task_id:
            removed = len(self._spans)
            self._spans.clear()
            self._task_traces.clear()
            return removed
        before = len(self._spans)
        self._spans = [item for item in self._spans if item.task_id != task_id]
        self._task_traces.pop(task_id, None)
        return before - len(self._spans)

    def stats(self) -> dict[str, Any]:
        by_kind: dict[str, int] = {}
        errors = 0
        for item in self._spans:
            by_kind[item.kind] = by_kind.get(item.kind, 0) + 1
            if item.status != STATUS_OK:
                errors += 1
        return {
            "schema_version": TRACE_SCHEMA_VERSION,
            "spans_stored": len(self._spans),
            "max_spans": self.max_spans,
            "retention_hours": self.retention_hours,
            "by_kind": by_kind,
            "error_spans": errors,
            "local_by_default": True,
            "external_export_enabled": bool(self.external_export_enabled and self.external_endpoint),
        }


__all__ = [
    "DEFAULT_MAX_SPANS",
    "DEFAULT_RETENTION_HOURS",
    "MAX_ATTR_CHARS",
    "MAX_SUMMARY_CHARS",
    "REDACTED",
    "SPAN_KINDS",
    "SPAN_MCP_CALL",
    "SPAN_MODEL_CALL",
    "SPAN_SANDBOX_RUN",
    "SPAN_TASK",
    "SPAN_TOOL_CALL",
    "SPAN_VERIFICATION",
    "SPAN_WORKFLOW_STEP",
    "STATUS_CANCELLED",
    "STATUS_DENIED",
    "STATUS_ERROR",
    "STATUS_OK",
    "STATUS_TIMEOUT",
    "TRACE_SCHEMA_VERSION",
    "Redactor",
    "Span",
    "TraceCollector",
    "new_span_id",
    "new_trace_id",
]
