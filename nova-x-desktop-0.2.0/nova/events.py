"""§91 Event-driven intelligence bus.

Components emit typed events; subscribers react. The bus exists so that a
completed code change can schedule tests without the code-change component
knowing the test runner exists.

Safety properties this module enforces, each with a test:

* **No circular loops.** Every event carries the chain of event *types* that
  caused it. An event whose type already appears in its own chain is refused,
  and a hard depth cap stops runaway recursion even for non-repeating chains.
* **No duplicate jobs.** A subscriber may declare an idempotency key; the same
  key is not processed twice inside the configured window. Emission dedupes on
  ``dedupe_key`` the same way.
* **No unbounded growth.** Payloads are size-capped, the pending queue and the
  persisted history are bounded, and old events are pruned on write.
* **No permission bypass.** A subscriber that names a tool is checked against
  the live autonomy policy *before* its handler runs. A denied or
  approval-required decision means the follow-up does not happen, and the bus
  records that it did not.

The bus never executes a tool itself. It only decides whether a subscriber may
run, and reports what it decided.
"""
from __future__ import annotations

import asyncio
import inspect
import json
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

EVENT_SCHEMA_VERSION = "nova-event-v1"

# The event vocabulary from §91. Types are namespaced so filters can subscribe to
# a whole family ("task.*") without listing every member.
EVENT_TYPES: tuple[str, ...] = (
    "task.created",
    "task.assigned",
    "task.completed",
    "task.failed",
    "task.cancelled",
    "model.connected",
    "model.disconnected",
    "command.started",
    "command.completed",
    "app.launched",
    "app.shutdown",
    "file.changed",
    "test.passed",
    "test.failed",
    "recovery.initiated",
    "permission.requested",
    "permission.granted",
    "permission.denied",
    "schedule.triggered",
    "memory.updated",
    "improvement.candidate_created",
    "integration.connected",
    "integration.unavailable",
    "security.event",
    "index.updated",
    "resource.pressure",
    "workflow.completed",
    "workflow.failed",
)

MAX_PAYLOAD_BYTES = 8_192
MAX_PENDING_EVENTS = 500
MAX_PERSISTED_EVENTS = 2_000
MAX_CAUSAL_DEPTH = 4
MAX_RETRIES = 2
RETRY_BACKOFF_SECONDS = 0.05
DEDUPE_WINDOW_SECONDS = 60.0
IDEMPOTENCY_WINDOW_SECONDS = 3_600.0

REQUIRED_EVENT_FIELDS = ("type", "source", "occurred_at")

# Outcome reasons, so monitoring can say *why* nothing happened.
OUTCOME_DELIVERED = "delivered"
OUTCOME_DUPLICATE = "duplicate"
OUTCOME_SCHEMA_INVALID = "schema_invalid"
OUTCOME_CYCLE = "cycle_refused"
OUTCOME_DEPTH_LIMITED = "depth_limited"
OUTCOME_NO_SUBSCRIBER = "no_subscriber"
OUTCOME_PERMISSION_DENIED = "permission_denied"
OUTCOME_IDEMPOTENT_SKIP = "idempotent_skip"
OUTCOME_HANDLER_FAILED = "handler_failed"
OUTCOME_DISABLED = "subscriber_disabled"
OUTCOME_QUEUE_FULL = "queue_full"
DELIVERY_OUTCOMES = (
    OUTCOME_DELIVERED,
    OUTCOME_DUPLICATE,
    OUTCOME_SCHEMA_INVALID,
    OUTCOME_CYCLE,
    OUTCOME_DEPTH_LIMITED,
    OUTCOME_NO_SUBSCRIBER,
    OUTCOME_PERMISSION_DENIED,
    OUTCOME_IDEMPOTENT_SKIP,
    OUTCOME_HANDLER_FAILED,
    OUTCOME_DISABLED,
    OUTCOME_QUEUE_FULL,
)


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(moment: datetime | None = None) -> str:
    return (moment or _now()).isoformat(timespec="microseconds")


def _payload_bytes(payload: dict[str, Any]) -> int:
    try:
        return len(json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8"))
    except (TypeError, ValueError):
        return MAX_PAYLOAD_BYTES + 1


@dataclass(frozen=True)
class Event:
    """One event. Immutable: a handler cannot rewrite history by mutating it."""

    type: str
    source: str
    occurred_at: str
    id: str = field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}")
    schema_version: str = EVENT_SCHEMA_VERSION
    task_id: str = ""
    correlation_id: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    causal_depth: int = 0
    causal_chain: tuple[str, ...] = ()
    dedupe_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "source": self.source,
            "occurred_at": self.occurred_at,
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "correlation_id": self.correlation_id,
            "payload": self.payload,
            "causal_depth": self.causal_depth,
            "causal_chain": list(self.causal_chain),
            "dedupe_key": self.dedupe_key,
        }

    def matches(self, pattern: str) -> bool:
        """``task.*`` matches ``task.created``; ``*`` matches everything."""
        if pattern in {"*", ""}:
            return True
        if pattern.endswith(".*"):
            return self.type.startswith(pattern[:-1])
        return self.type == pattern

    @classmethod
    def validate(cls, raw: Any) -> tuple[Event | None, list[str]]:
        """Reject anything that is not a well-formed event, with reasons."""
        errors: list[str] = []
        if not isinstance(raw, dict):
            return None, ["an event must be a JSON object"]
        for key in REQUIRED_EVENT_FIELDS:
            if not str(raw.get(key, "")).strip():
                errors.append(f"missing required field '{key}'")
        event_type = str(raw.get("type", ""))
        if event_type and event_type not in EVENT_TYPES:
            errors.append(f"unknown event type '{event_type}'")
        occurred_at = str(raw.get("occurred_at", ""))
        if occurred_at:
            try:
                datetime.fromisoformat(occurred_at)
            except ValueError:
                errors.append("occurred_at is not an ISO-8601 timestamp")
        payload = raw.get("payload", {})
        if payload is not None and not isinstance(payload, dict):
            errors.append("payload must be a JSON object")
        if isinstance(payload, dict) and _payload_bytes(payload) > MAX_PAYLOAD_BYTES:
            errors.append(f"payload exceeds the {MAX_PAYLOAD_BYTES}-byte limit")
        if errors:
            return None, errors
        try:
            depth = int(raw.get("causal_depth", 0) or 0)
        except (TypeError, ValueError):
            depth = 0
            errors.append("causal_depth must be an integer")
        chain = raw.get("causal_chain") or ()
        if not isinstance(chain, (list, tuple)):
            return None, [*errors, "causal_chain must be a list of event types"]
        event = cls(
            type=event_type,
            source=str(raw.get("source", "")),
            occurred_at=occurred_at,
            id=str(raw.get("id") or f"evt-{uuid.uuid4().hex[:12]}"),
            schema_version=str(raw.get("schema_version") or EVENT_SCHEMA_VERSION),
            task_id=str(raw.get("task_id", "") or ""),
            correlation_id=str(raw.get("correlation_id", "") or ""),
            payload=dict(payload or {}),
            causal_depth=max(0, depth),
            causal_chain=tuple(str(item) for item in chain),
            dedupe_key=str(raw.get("dedupe_key", "") or ""),
        )
        return (event, errors)


@dataclass
class Delivery:
    """What happened to one (event, subscriber) pair."""

    event_id: str
    event_type: str
    subscriber_id: str
    outcome: str
    detail: str = ""
    attempts: int = 0
    delivered_at: str = field(default_factory=_iso)
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "subscriber_id": self.subscriber_id,
            "outcome": self.outcome,
            "detail": self.detail,
            "attempts": self.attempts,
            "delivered_at": self.delivered_at,
            "duration_ms": self.duration_ms,
        }


EventHandler = Callable[[Event, "EventBus"], Any]
IdempotencyFn = Callable[[Event], str]
PermissionCheck = Callable[[str, dict[str, Any]], dict[str, Any]]


@dataclass
class Subscription:
    """A subscriber, its filter, and the authority it needs to act."""

    id: str
    event_patterns: tuple[str, ...]
    handler: EventHandler
    description: str = ""
    # When set, the handler is only invoked if the autonomy policy allows this
    # tool with the arguments the handler would use. This is what stops an event
    # from laundering an unauthorized action.
    requires_tool: str = ""
    permission_arguments: Callable[[Event], dict[str, Any]] | None = None
    filter_predicate: Callable[[Event], bool] | None = None
    idempotency_key: IdempotencyFn | None = None
    max_retries: int = MAX_RETRIES
    enabled: bool = True
    processed_keys: dict[str, datetime] = field(default_factory=dict)

    def interested(self, event: Event) -> bool:
        if not self.enabled:
            return False
        if not any(event.matches(pattern) for pattern in self.event_patterns):
            return False
        if self.filter_predicate is None:
            return True
        try:
            return bool(self.filter_predicate(event))
        except Exception as exc:
            logger.warning("event filter %s raised %s; treating as no match", self.id, exc)
            return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "event_patterns": list(self.event_patterns),
            "description": self.description,
            "requires_tool": self.requires_tool,
            "max_retries": self.max_retries,
            "enabled": self.enabled,
            "has_filter": self.filter_predicate is not None,
            "has_idempotency_key": self.idempotency_key is not None,
            "processed_keys": len(self.processed_keys),
        }


@dataclass
class EventBus:
    """Bounded, permission-aware in-process event dispatch."""

    permission_check: PermissionCheck | None = None
    persist: Callable[[Event, list[Delivery]], None] | None = None
    max_pending_events: int = MAX_PENDING_EVENTS
    max_persisted_events: int = MAX_PERSISTED_EVENTS
    max_causal_depth: int = MAX_CAUSAL_DEPTH
    dedupe_window_seconds: float = DEDUPE_WINDOW_SECONDS
    idempotency_window_seconds: float = IDEMPOTENCY_WINDOW_SECONDS
    _subscriptions: dict[str, Subscription] = field(default_factory=dict, init=False)
    _pending: list[Event] = field(default_factory=list, init=False)
    _history: list[Delivery] = field(default_factory=list, init=False)
    _seen_dedupe: dict[str, datetime] = field(default_factory=dict, init=False)
    _counters: dict[str, int] = field(default_factory=dict, init=False)
    _emitted: int = field(default=0, init=False)

    # -- subscription management

    def subscribe(self, subscription: Subscription) -> Subscription:
        if subscription.id in self._subscriptions:
            raise ValueError(f"Subscriber already registered: {subscription.id}")
        if not subscription.event_patterns:
            raise ValueError("A subscription must declare at least one event pattern")
        for pattern in subscription.event_patterns:
            if pattern not in {"*", ""} and not pattern.endswith(".*") and pattern not in EVENT_TYPES:
                raise ValueError(f"Subscription '{subscription.id}' uses unknown event type '{pattern}'")
        if subscription.requires_tool and self.permission_check is None:
            # Refusing here is the point: a subscriber that needs authority must
            # be attached to a policy, never to a bus that cannot check one.
            raise ValueError(
                f"Subscription '{subscription.id}' requires tool '{subscription.requires_tool}' "
                "but the bus has no permission_check; it could not be authorized."
            )
        if subscription.max_retries < 0 or subscription.max_retries > MAX_RETRIES:
            raise ValueError(f"max_retries must be between 0 and {MAX_RETRIES}")
        self._subscriptions[subscription.id] = subscription
        return subscription

    def unsubscribe(self, subscription_id: str) -> bool:
        return self._subscriptions.pop(subscription_id, None) is not None

    def set_enabled(self, subscription_id: str, enabled: bool) -> bool:
        subscription = self._subscriptions.get(subscription_id)
        if subscription is None:
            return False
        subscription.enabled = bool(enabled)
        return True

    def subscriptions(self) -> list[dict[str, Any]]:
        return [item.to_dict() for item in self._subscriptions.values()]

    # -- emission

    async def emit(self, raw: dict[str, Any] | Event) -> list[Delivery]:
        """Validate, dedupe, bound and dispatch one event."""
        if isinstance(raw, Event):
            event, errors = Event.validate(raw.to_dict())
        else:
            event, errors = Event.validate(raw)
        if event is None:
            self._count(OUTCOME_SCHEMA_INVALID)
            delivery = Delivery(
                event_id=str(raw.get("id", "") if isinstance(raw, dict) else ""),
                event_type=str(raw.get("type", "") if isinstance(raw, dict) else getattr(raw, "type", "")),
                subscriber_id="",
                outcome=OUTCOME_SCHEMA_INVALID,
                detail="; ".join(errors)[:400],
            )
            self._record_history(delivery)
            return [delivery]

        self._emitted += 1
        deliveries: list[Delivery] = []

        if event.causal_depth > self.max_causal_depth:
            deliveries.append(self._refuse(event, OUTCOME_DEPTH_LIMITED, f"causal depth {event.causal_depth} exceeds {self.max_causal_depth}"))
            self._persist(event, deliveries)
            return deliveries
        if event.type in event.causal_chain:
            chain = " -> ".join([*event.causal_chain, event.type])
            deliveries.append(self._refuse(event, OUTCOME_CYCLE, f"event type repeats in its own causal chain: {chain}"))
            self._persist(event, deliveries)
            return deliveries
        if event.dedupe_key and self._is_duplicate(event.dedupe_key):
            deliveries.append(self._refuse(event, OUTCOME_DUPLICATE, f"dedupe key '{event.dedupe_key}' seen within {self.dedupe_window_seconds:g}s"))
            self._persist(event, deliveries)
            return deliveries

        if len(self._pending) >= self.max_pending_events:
            # Dropping the oldest rather than the newest keeps the queue bounded
            # without silently discarding what just happened.
            dropped = self._pending.pop(0)
            self._count(OUTCOME_QUEUE_FULL)
            logger.warning("event queue full (%d); dropped oldest event %s", self.max_pending_events, dropped.id)
        self._pending.append(event)

        interested = [item for item in self._subscriptions.values() if item.interested(event)]
        if not interested:
            deliveries.append(self._refuse(event, OUTCOME_NO_SUBSCRIBER, "no enabled subscriber matched this event type"))
        for subscription in interested:
            delivery = await self._deliver(event, subscription)
            deliveries.append(delivery)
        self._pending = [item for item in self._pending if item.id != event.id]
        self._persist(event, deliveries)
        return deliveries

    async def emit_child(self, parent: Event, event_type: str, source: str, payload: dict[str, Any] | None = None) -> list[Delivery]:
        """Emit a follow-up event, carrying the causal chain for loop detection."""
        child = Event(
            type=event_type,
            source=source,
            occurred_at=_iso(),
            task_id=parent.task_id,
            correlation_id=parent.correlation_id or parent.id,
            payload=dict(payload or {}),
            causal_depth=parent.causal_depth + 1,
            causal_chain=(*parent.causal_chain, parent.type),
        )
        return await self.emit(child)

    def _refuse(self, event: Event, outcome: str, detail: str) -> Delivery:
        self._count(outcome)
        delivery = Delivery(event_id=event.id, event_type=event.type, subscriber_id="", outcome=outcome, detail=detail[:400])
        self._record_history(delivery)
        return delivery

    def _is_duplicate(self, dedupe_key: str) -> bool:
        now = _now()
        self._prune_window(self._seen_dedupe, now, self.dedupe_window_seconds)
        if dedupe_key in self._seen_dedupe:
            return True
        self._seen_dedupe[dedupe_key] = now
        return False

    @staticmethod
    def _prune_window(store: dict[str, datetime], now: datetime, window: float) -> None:
        expired = [key for key, seen_at in store.items() if (now - seen_at).total_seconds() > window]
        for key in expired:
            store.pop(key, None)

    # -- delivery

    async def _deliver(self, event: Event, subscription: Subscription) -> Delivery:
        started = datetime.now(UTC)

        if subscription.requires_tool:
            arguments = {}
            if subscription.permission_arguments is not None:
                try:
                    arguments = dict(subscription.permission_arguments(event) or {})
                except Exception as exc:
                    return self._finish(
                        event,
                        subscription,
                        OUTCOME_PERMISSION_DENIED,
                        f"could not derive permission arguments: {type(exc).__name__}",
                        started,
                    )
            if self.permission_check is None:
                return self._finish(event, subscription, OUTCOME_PERMISSION_DENIED, "no permission check is configured", started)
            try:
                decision = self.permission_check(subscription.requires_tool, arguments)
            except Exception as exc:
                return self._finish(
                    event,
                    subscription,
                    OUTCOME_PERMISSION_DENIED,
                    f"permission check failed: {type(exc).__name__}",
                    started,
                )
            action = str(decision.get("action", "deny")) if isinstance(decision, dict) else "deny"
            if action != "allow":
                reason = str(decision.get("reason", "")) if isinstance(decision, dict) else ""
                return self._finish(
                    event,
                    subscription,
                    OUTCOME_PERMISSION_DENIED,
                    f"policy returned '{action}' for '{subscription.requires_tool}': {reason}"[:400],
                    started,
                )

        if subscription.idempotency_key is not None:
            try:
                key = str(subscription.idempotency_key(event) or "")
            except Exception as exc:
                key = ""
                logger.warning("idempotency key for %s raised %s", subscription.id, exc)
            if key:
                now = _now()
                self._prune_window(subscription.processed_keys, now, self.idempotency_window_seconds)
                if key in subscription.processed_keys:
                    return self._finish(event, subscription, OUTCOME_IDEMPOTENT_SKIP, f"idempotency key '{key}' already processed", started)
                subscription.processed_keys[key] = now

        attempts = 0
        last_error = ""
        while attempts <= subscription.max_retries:
            attempts += 1
            try:
                result = subscription.handler(event, self)
                if inspect.isawaitable(result):
                    await result
                return self._finish(event, subscription, OUTCOME_DELIVERED, "", started, attempts)
            except asyncio.CancelledError:
                # Cancellation is the user's control, not a transient failure.
                raise
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempts <= subscription.max_retries:
                    await asyncio.sleep(RETRY_BACKOFF_SECONDS * attempts)
        return self._finish(event, subscription, OUTCOME_HANDLER_FAILED, f"failed after {attempts} attempt(s): {last_error}"[:400], started, attempts)

    def _finish(
        self,
        event: Event,
        subscription: Subscription,
        outcome: str,
        detail: str,
        started: datetime,
        attempts: int = 0,
    ) -> Delivery:
        self._count(outcome)
        delivery = Delivery(
            event_id=event.id,
            event_type=event.type,
            subscriber_id=subscription.id,
            outcome=outcome,
            detail=detail,
            attempts=attempts,
            duration_ms=round((datetime.now(UTC) - started).total_seconds() * 1000, 3),
        )
        self._record_history(delivery)
        return delivery

    # -- bookkeeping

    def _count(self, outcome: str) -> None:
        self._counters[outcome] = self._counters.get(outcome, 0) + 1

    def _record_history(self, delivery: Delivery) -> None:
        self._history.append(delivery)
        overflow = len(self._history) - self.max_persisted_events
        if overflow > 0:
            del self._history[:overflow]

    def _persist(self, event: Event, deliveries: list[Delivery]) -> None:
        if self.persist is None:
            return
        try:
            self.persist(event, deliveries)
        except Exception as exc:
            # Losing the audit record is worth one warning, not a crashed bus.
            logger.warning("event persistence failed for %s: %s", event.id, exc)

    def history(self, *, limit: int = 100, outcome: str = "", event_type: str = "") -> list[dict[str, Any]]:
        rows = self._history
        if outcome:
            rows = [item for item in rows if item.outcome == outcome]
        if event_type:
            rows = [item for item in rows if item.event_type == event_type or item.event_type.startswith(event_type.rstrip("*"))]
        return [item.to_dict() for item in rows[-max(1, min(limit, self.max_persisted_events)) :]]

    def stats(self) -> dict[str, Any]:
        counters = dict.fromkeys(DELIVERY_OUTCOMES, 0)
        counters.update(self._counters)
        return {
            "schema_version": EVENT_SCHEMA_VERSION,
            "emitted": self._emitted,
            "subscribers": len(self._subscriptions),
            "enabled_subscribers": sum(1 for item in self._subscriptions.values() if item.enabled),
            "pending": len(self._pending),
            "max_pending_events": self.max_pending_events,
            "history_entries": len(self._history),
            "max_causal_depth": self.max_causal_depth,
            "dedupe_keys_tracked": len(self._seen_dedupe),
            "outcomes": counters,
            "delivery_rate": round(counters[OUTCOME_DELIVERED] / self._emitted, 4) if self._emitted else None,
            "blocked_by_permission": counters[OUTCOME_PERMISSION_DENIED],
            "note": (
                "Counters describe dispatch decisions only. A delivered event does not mean the "
                "follow-up action succeeded; the action reports its own outcome."
            ),
        }


__all__ = [
    "DEDUPE_WINDOW_SECONDS",
    "DELIVERY_OUTCOMES",
    "EVENT_SCHEMA_VERSION",
    "EVENT_TYPES",
    "IDEMPOTENCY_WINDOW_SECONDS",
    "MAX_CAUSAL_DEPTH",
    "MAX_PAYLOAD_BYTES",
    "MAX_PENDING_EVENTS",
    "MAX_PERSISTED_EVENTS",
    "MAX_RETRIES",
    "OUTCOME_CYCLE",
    "OUTCOME_DELIVERED",
    "OUTCOME_DEPTH_LIMITED",
    "OUTCOME_DISABLED",
    "OUTCOME_DUPLICATE",
    "OUTCOME_HANDLER_FAILED",
    "OUTCOME_IDEMPOTENT_SKIP",
    "OUTCOME_NO_SUBSCRIBER",
    "OUTCOME_PERMISSION_DENIED",
    "OUTCOME_QUEUE_FULL",
    "OUTCOME_SCHEMA_INVALID",
    "Delivery",
    "Event",
    "EventBus",
    "Subscription",
]
