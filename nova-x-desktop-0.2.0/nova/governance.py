"""§111 Privacy-first data governance and §102 System health & diagnostics center.

Gives the operator a unified, factual view of:

1. **Everything stored locally or transmitted externally (§111):** conversations,
   long-term memory / procedures, indexed files, provider data-transmission
   records, cached context/responses, diagnostic spans, integration credentials
   (names and storage backends only — never secret values), scheduled goals, and
   exported artifacts — plus retention controls, export, deletion, and a
   pre-transmission gate that refuses sending local files to third-party
   services without both task justification and explicit permission.
2. **System health and redacted diagnostics (§102):** application & worker
   status, active tasks, provider availability, API errors, CPU/RAM/disk
   pressure, SQLite status, crashes/degraded components, scheduled jobs, active
   NOVA-started processes, security events, failed integrations and pending
   updates — refreshed on demand or via events (no background polling loop) and
   exportable as a shareable, secret-redacted diagnostic bundle.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nova import __version__
from nova.db import Database
from nova.knowledge import KnowledgeStore
from nova.observability import Redactor, TraceCollector
from nova.resources import ResourceManager

GOVERNANCE_SCHEMA_VERSION = "nova-governance-v1"
DIAGNOSTIC_SCHEMA_VERSION = "nova-diagnostics-v1"

CONTENT_PROMPT_TEXT = "prompt_text"
CONTENT_LOCAL_FILE = "local_file"
CONTENT_SCREENSHOT = "screenshot"
CONTENT_TELEMETRY = "telemetry"
CONTENT_SEARCH_QUERY = "search_query"
CONTENT_KINDS = (
    CONTENT_PROMPT_TEXT,
    CONTENT_LOCAL_FILE,
    CONTENT_SCREENSHOT,
    CONTENT_TELEMETRY,
    CONTENT_SEARCH_QUERY,
)


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


@dataclass
class RetentionPolicy:
    """User-configurable retention and transmission rules (§111)."""

    conversation_retention_days: int = 90
    trace_retention_hours: float = 72.0
    max_transmission_chars: int = 24_000
    excluded_paths: tuple[str, ...] = ("~/.ssh", "~/.gnupg", ".env", "secrets/")
    allow_third_party_file_upload: bool = False
    allow_screenshot_upload: bool = False
    disclose_provider_transmission: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "conversation_retention_days": self.conversation_retention_days,
            "trace_retention_hours": self.trace_retention_hours,
            "max_transmission_chars": self.max_transmission_chars,
            "excluded_paths": list(self.excluded_paths),
            "allow_third_party_file_upload": self.allow_third_party_file_upload,
            "allow_screenshot_upload": self.allow_screenshot_upload,
            "disclose_provider_transmission": self.disclose_provider_transmission,
        }


@dataclass(frozen=True)
class TransmissionDecision:
    allowed: bool
    destination: str
    content_kind: str
    reason: str
    disclosures: tuple[str, ...] = ()
    decided_at: str = field(default_factory=_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "destination": self.destination,
            "content_kind": self.content_kind,
            "reason": self.reason,
            "disclosures": list(self.disclosures),
            "decided_at": self.decided_at,
        }


@dataclass
class PrivacyGovernor:
    """§111 Unified data inventory, transmission gate, retention and deletion."""

    db: Database
    policy: RetentionPolicy = field(default_factory=RetentionPolicy)
    redactor: Redactor = field(default_factory=Redactor)
    knowledge_store: KnowledgeStore | None = None
    traces: TraceCollector | None = None
    artifacts_dir: Path | None = None
    credential_descriptors: Callable[[], list[dict[str, Any]]] | None = None
    _transmissions: list[dict[str, Any]] = field(default_factory=list, init=False)
    _cached_entries_provider: Callable[[], int] | None = None

    def update_policy(self, **changes: Any) -> RetentionPolicy:
        current = self.policy.to_dict()
        for key, value in changes.items():
            if key not in current:
                raise ValueError(f"Unknown privacy policy field: {key}")
            if key == "excluded_paths":
                current[key] = tuple(str(item) for item in (value or ()))
            elif isinstance(current[key], bool):
                current[key] = bool(value)
            elif isinstance(current[key], int):
                current[key] = max(1, int(value))
            elif isinstance(current[key], float):
                current[key] = max(0.1, float(value))
        self.policy = RetentionPolicy(**current)
        if self.traces is not None:
            self.traces.retention_hours = self.policy.trace_retention_hours
            self.traces.apply_retention()
        return self.policy

    def authorize_transmission(
        self,
        *,
        destination: str,
        content_kind: str,
        char_count: int = 0,
        source_path: str = "",
        task_justified: bool = False,
        permission_granted: bool = False,
        is_local_destination: bool = False,
    ) -> TransmissionDecision:
        """Gate outbound data before it leaves the machine (§111)."""
        if content_kind not in CONTENT_KINDS:
            decision = TransmissionDecision(False, destination, content_kind, f"unknown content kind '{content_kind}'")
            self._record_transmission(decision, char_count)
            return decision

        if source_path:
            normalized = source_path.replace("\\", "/")
            for excluded in self.policy.excluded_paths:
                token = excluded.expanduser() if hasattr(excluded, "expanduser") else str(excluded).lstrip("~/")
                if token and (normalized.endswith(token.rstrip("/")) or token.rstrip("/") in normalized):
                    decision = TransmissionDecision(
                        False,
                        destination,
                        content_kind,
                        f"path matches privacy exclusion '{excluded}'",
                    )
                    self._record_transmission(decision, char_count)
                    return decision

        if is_local_destination:
            decision = TransmissionDecision(
                True,
                destination,
                content_kind,
                "destination is local to this machine",
            )
            self._record_transmission(decision, char_count)
            return decision

        if content_kind == CONTENT_LOCAL_FILE:
            # §111: Never send local files to a third-party service simply because
            # an available integration supports file uploads.
            if not self.policy.allow_third_party_file_upload:
                decision = TransmissionDecision(
                    False,
                    destination,
                    content_kind,
                    "third-party local file uploads are disabled by privacy policy",
                )
                self._record_transmission(decision, char_count)
                return decision
            if not (task_justified and permission_granted):
                decision = TransmissionDecision(
                    False,
                    destination,
                    content_kind,
                    "sending a local file externally requires both task justification and granted permission",
                )
                self._record_transmission(decision, char_count)
                return decision

        if content_kind == CONTENT_SCREENSHOT and not (
            self.policy.allow_screenshot_upload and task_justified and permission_granted
        ):
            decision = TransmissionDecision(
                False,
                destination,
                content_kind,
                "uploading screenshots requires explicit policy opt-in, task justification and permission",
            )
            self._record_transmission(decision, char_count)
            return decision

        if char_count > self.policy.max_transmission_chars:
            decision = TransmissionDecision(
                False,
                destination,
                content_kind,
                f"payload of {char_count} chars exceeds max_transmission_chars ({self.policy.max_transmission_chars})",
            )
            self._record_transmission(decision, char_count)
            return decision

        if not task_justified:
            decision = TransmissionDecision(
                False,
                destination,
                content_kind,
                "external transmission is not justified by an active task",
            )
            self._record_transmission(decision, char_count)
            return decision

        disclosures: list[str] = []
        if self.policy.disclose_provider_transmission:
            disclosures.append(
                f"Sending {char_count} chars of '{content_kind}' to external destination '{destination}'; "
                "subject to that provider's retention policy."
            )
        decision = TransmissionDecision(
            True,
            destination,
            content_kind,
            "justified by task and within configured privacy limits",
            tuple(disclosures),
        )
        self._record_transmission(decision, char_count)
        return decision

    def _record_transmission(self, decision: TransmissionDecision, char_count: int) -> None:
        entry = {**decision.to_dict(), "char_count": max(0, int(char_count))}
        self._transmissions.append(entry)
        if len(self._transmissions) > 500:
            del self._transmissions[:-500]

    def inventory(self) -> dict[str, Any]:
        """Unified §111 view of all nine governed data categories."""
        conversations = self.db.list_conversations(limit=500)
        procedures = self.db.list_procedures(limit=500)
        observations = self.db.list_observations(limit=500)
        goals = self.db.list_goals()
        knowledge = (
            self.knowledge_store.stats()
            if self.knowledge_store is not None
            else {"documents": 0, "chunks": 0, "note": "knowledge store not attached"}
        )
        trace_stats = self.traces.stats() if self.traces is not None else {"spans_stored": 0}
        credentials = []
        if self.credential_descriptors is not None:
            for item in self.credential_descriptors():
                # Never expose credential values — only identifier, backend and configured bool.
                credentials.append(
                    {
                        "name": str(item.get("name", "")),
                        "storage": str(item.get("storage", "keyring_or_env")),
                        "configured": bool(item.get("configured", False)),
                    }
                )
        artifacts: list[str] = []
        if self.artifacts_dir is not None and self.artifacts_dir.is_dir():
            artifacts = sorted(
                str(p.relative_to(self.artifacts_dir))
                for p in self.artifacts_dir.rglob("*")
                if p.is_file()
            )[:200]
        cached_count = self._cached_entries_provider() if self._cached_entries_provider is not None else 0
        return {
            "schema_version": GOVERNANCE_SCHEMA_VERSION,
            "generated_at": _iso(),
            "policy": self.policy.to_dict(),
            "locally_stored_conversations": {
                "count": len(conversations),
                "conversations": [{"id": c["id"], "title": c["title"], "updated_at": c["updated_at"]} for c in conversations[:50]],
            },
            "long_term_memory": {
                "procedures": len(procedures),
                "world_model_observations": len(observations),
            },
            "indexed_files": {
                "documents": knowledge.get("documents", 0),
                "chunks": knowledge.get("chunks", 0),
                "excluded_directories": knowledge.get("excluded_directories", []),
            },
            "provider_data_transmissions": {
                "recorded": len(self._transmissions),
                "allowed": sum(1 for item in self._transmissions if item["allowed"]),
                "blocked": sum(1 for item in self._transmissions if not item["allowed"]),
                "recent": self._transmissions[-25:],
            },
            "cached_responses": {"entries": cached_count},
            "diagnostic_logs": trace_stats,
            "integration_credentials": {
                "count": len(credentials),
                "descriptors": credentials,
                "values_exposed": False,
            },
            "scheduled_task_records": {
                "count": len(goals),
                "enabled": sum(1 for g in goals if g.get("enabled")),
            },
            "exported_artifacts": {
                "count": len(artifacts),
                "files": artifacts,
            },
        }

    def export_user_data(self) -> dict[str, Any]:
        """Portable, secret-redacted export of user-owned conversations, procedures and goals."""
        conversations = self.db.list_conversations(limit=200)
        exported_convos = []
        for convo in conversations:
            messages = self.db.get_messages(convo["id"], limit=200)
            exported_convos.append(
                {
                    "id": convo["id"],
                    "title": self.redactor.scrub_text(convo["title"], max_chars=200),
                    "messages": [
                        {
                            "role": msg["role"],
                            "content": self.redactor.scrub_text(msg["content"], max_chars=4_000),
                            "created_at": msg["created_at"],
                        }
                        for msg in messages
                    ],
                }
            )
        return {
            "schema_version": GOVERNANCE_SCHEMA_VERSION,
            "exported_at": _iso(),
            "conversations": exported_convos,
            "procedures": self.redactor.scrub(self.db.list_procedures(limit=200), max_chars=1_000),
            "scheduled_goals": self.redactor.scrub(self.db.list_goals(), max_chars=1_000),
            "policy": self.policy.to_dict(),
        }

    def delete_category(self, category: str) -> dict[str, Any]:
        """Delete a governed category on operator request (§111)."""
        removed = 0
        if category == "conversations":
            for convo in self.db.list_conversations(limit=1_000):
                if self.db.delete_conversation(convo["id"]):
                    removed += 1
        elif category == "indexed_files":
            if self.knowledge_store is not None:
                removed = self.knowledge_store.forget(everything=True)["removed_documents"]
        elif category == "diagnostic_logs":
            if self.traces is not None:
                removed = self.traces.clear()
        elif category == "command_history":
            removed = self.db.clear_command_history()
        elif category == "procedures":
            for proc in self.db.list_procedures(limit=1_000):
                if self.db.delete_procedure(proc["id"]):
                    removed += 1
        elif category == "transmission_log":
            removed = len(self._transmissions)
            self._transmissions.clear()
        else:
            raise ValueError(f"Unsupported deletion category: {category}")
        return {"category": category, "removed": removed, "deleted_at": _iso()}


@dataclass
class SystemHealthCenter:
    """§102 Native system-health panel backend and redacted diagnostic bundler.

    Event-driven / on-demand by design: there is no background polling thread.
    """

    db: Database
    resources: ResourceManager = field(default_factory=ResourceManager)
    redactor: Redactor = field(default_factory=Redactor)
    traces: TraceCollector | None = None
    worker_status_fn: Callable[[], dict[str, Any]] | None = None
    provider_status_fn: Callable[[], dict[str, Any]] | None = None
    processes_fn: Callable[[], list[dict[str, Any]]] | None = None
    integrations_fn: Callable[[], list[dict[str, Any]]] | None = None
    pending_updates_fn: Callable[[], dict[str, Any]] | None = None
    _crashes: list[dict[str, Any]] = field(default_factory=list, init=False)
    _security_events: list[dict[str, Any]] = field(default_factory=list, init=False)
    _api_errors: list[dict[str, Any]] = field(default_factory=list, init=False)
    _listeners: list[Callable[[dict[str, Any]], None]] = field(default_factory=list, init=False)

    def add_listener(self, callback: Callable[[dict[str, Any]], None]) -> None:
        self._listeners.append(callback)

    def _notify(self, event: dict[str, Any]) -> None:
        for callback in list(self._listeners):
            try:
                callback(event)
            except Exception:
                continue

    def record_crash(self, component: str, error: str) -> None:
        entry = {
            "component": self.redactor.scrub_text(component, max_chars=80),
            "error": self.redactor.scrub_text(error, max_chars=300),
            "occurred_at": _iso(),
        }
        self._crashes.append(entry)
        del self._crashes[:-50]
        self._notify({"kind": "crash", **entry})

    def record_security_event(self, category: str, detail: str, *, severity: str = "warning") -> None:
        entry = {
            "category": self.redactor.scrub_text(category, max_chars=80),
            "severity": severity,
            "detail": self.redactor.scrub_text(detail, max_chars=300),
            "occurred_at": _iso(),
        }
        self._security_events.append(entry)
        del self._security_events[:-100]
        self._notify({"kind": "security_event", **entry})

    def record_api_error(self, provider: str, detail: str, *, status_code: int | None = None) -> None:
        entry = {
            "provider": self.redactor.scrub_text(provider, max_chars=80),
            "status_code": status_code,
            "detail": self.redactor.scrub_text(detail, max_chars=300),
            "occurred_at": _iso(),
        }
        self._api_errors.append(entry)
        del self._api_errors[:-100]
        self._notify({"kind": "api_error", **entry})

    def status(self) -> dict[str, Any]:
        """Collect all 15 §102 health indicators in a single on-demand snapshot."""
        db_ok = False
        active_tasks = 0
        goals: list[dict[str, Any]] = []
        try:
            db_ok = bool(self.db.health_check())
            tasks = self.db.list_tasks(limit=100)
            active_tasks = sum(1 for t in tasks if t.get("state") in {"queued", "running", "waiting_approval"})
            goals = self.db.list_goals()
        except Exception as exc:
            self.record_crash("database", f"{type(exc).__name__}: {exc}")

        budget = self.resources.assess()
        sample = budget.sample
        worker = self.worker_status_fn() if self.worker_status_fn is not None else {"running": True, "mode": "on_demand"}
        provider = (
            self.provider_status_fn()
            if self.provider_status_fn is not None
            else {"available": False, "reason": "no provider status callback attached"}
        )
        processes = self.processes_fn() if self.processes_fn is not None else []
        integrations = self.integrations_fn() if self.integrations_fn is not None else []
        failed_integrations = [item for item in integrations if item.get("status") in {"unavailable", "error", "disconnected"}]
        updates = self.pending_updates_fn() if self.pending_updates_fn is not None else {"update_available": False, "current_version": __version__}

        app_status = "healthy"
        if not db_ok or self._crashes:
            app_status = "degraded"
        elif budget.pressure in {"high", "critical"} or not provider.get("available", False):
            app_status = "degraded" if not provider.get("available", False) else "constrained"

        return {
            "schema_version": DIAGNOSTIC_SCHEMA_VERSION,
            "checked_at": _iso(),
            "version": __version__,
            "polling_mode": "event_driven_and_on_demand",
            "application_status": app_status,
            "background_worker": worker,
            "active_task_count": active_tasks,
            "provider_availability": self.redactor.scrub(provider),
            "api_errors": {"count": len(self._api_errors), "recent": list(self._api_errors[-10:])},
            "resource_usage": budget.to_dict(),
            "cpu_and_memory_pressure": {
                "pressure": budget.pressure,
                "cpu_count": sample.cpu_count if sample else 0,
                "load_per_cpu": sample.load_per_cpu if sample else 0.0,
                "memory_available_mb": sample.memory_available_mb if sample else 0,
                "memory_available_ratio": sample.memory_available_ratio if sample else None,
            },
            "disk_space": {
                "free_mb": sample.disk_free_mb if sample else 0,
                "total_mb": sample.disk_total_mb if sample else 0,
                "warnings": [w for w in budget.warnings if "disk" in w.lower()],
            },
            "database_status": {"healthy": db_ok, "path": str(self.db.path)},
            "recent_crashes": {"count": len(self._crashes), "recent": list(self._crashes[-10:])},
            "scheduled_jobs": {
                "total": len(goals),
                "enabled": sum(1 for g in goals if g.get("enabled")),
                "jobs": [{"id": g["id"], "name": g["name"], "enabled": g["enabled"], "next_run_at": g.get("next_run_at")} for g in goals[:20]],
            },
            "active_nova_processes": [
                self.redactor.scrub(proc) for proc in processes if proc.get("active", True) and proc.get("started_by") in {"nova", True}
            ],
            "recent_security_events": {"count": len(self._security_events), "recent": list(self._security_events[-15:])},
            "failed_integrations": [self.redactor.scrub(item) for item in failed_integrations],
            "pending_updates": self.redactor.scrub(updates),
        }

    def export_diagnostic_report(self, *, configuration_checks: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create an exportable, secret-redacted diagnostic report (§102)."""
        health = self.status()
        spans = self.traces.list_spans(limit=50) if self.traces is not None else []
        return {
            "schema_version": DIAGNOSTIC_SCHEMA_VERSION,
            "exported_at": _iso(),
            "version": __version__,
            "health": self.redactor.scrub(health),
            "configuration_checks": self.redactor.scrub(configuration_checks or {}),
            "recent_spans": spans,
            "privacy_guarantee": (
                "Passwords, API keys, session tokens and unrelated private file contents are "
                "excluded or redacted before export."
            ),
        }


__all__ = [
    "CONTENT_KINDS",
    "CONTENT_LOCAL_FILE",
    "CONTENT_PROMPT_TEXT",
    "CONTENT_SCREENSHOT",
    "CONTENT_SEARCH_QUERY",
    "CONTENT_TELEMETRY",
    "DIAGNOSTIC_SCHEMA_VERSION",
    "GOVERNANCE_SCHEMA_VERSION",
    "PrivacyGovernor",
    "RetentionPolicy",
    "SystemHealthCenter",
    "TransmissionDecision",
]
