"""§95 Context and memory optimization engine.

Assembles working context within a strict character budget while enforcing five
structural guarantees:

1. **Compartmentalized storage.** Conversation history, durable task state,
   user-approved memory, project knowledge and confidential credentials live in
   distinct compartments. Credential metadata may never enter a model prompt.
2. **Protected anchors.** Active objectives, explicit constraints, permission /
   autonomy boundaries, recent error evidence and unresolved blockers are never
   compressed away, even when the remaining budget is tight.
3. **Facts vs hypotheses.** Items backed by observational provenance
   (``tool_result``, ``test``, ``user``) are emitted under ``verified_facts``;
   model inferences and unverified external claims stay under ``hypotheses``.
4. **Stage summarization.** Completed stages of long tasks are condensed
   extractively (outcome + evidence ref), freeing budget for active steps.
5. **Deduplication & high-impact re-verification.** Context blocks carry a
   content fingerprint so identical context is not resent unnecessarily, and
   high-impact actions require re-reading stale or summarized source material.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from nova.knowledge import CURRENCY_STALE, KnowledgeStore
from nova.observability import Redactor

COMPARTMENT_CONVERSATION = "conversation_history"
COMPARTMENT_TASK_STATE = "durable_task_state"
COMPARTMENT_APPROVED_MEMORY = "approved_memory"
COMPARTMENT_PROJECT_KNOWLEDGE = "project_knowledge"
COMPARTMENT_CREDENTIALS = "confidential_credentials"
COMPARTMENTS = (
    COMPARTMENT_CONVERSATION,
    COMPARTMENT_TASK_STATE,
    COMPARTMENT_APPROVED_MEMORY,
    COMPARTMENT_PROJECT_KNOWLEDGE,
    COMPARTMENT_CREDENTIALS,
)

VERIFIED_PROVENANCES = frozenset({"user", "tool_result", "test"})
DEFAULT_CONTEXT_BUDGET_CHARS = 16_000
MIN_CONTEXT_BUDGET_CHARS = 1_200
STALE_CONTEXT_MINUTES = 60.0


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(moment: datetime | None = None) -> str:
    return (moment or _now()).isoformat(timespec="microseconds")


def _tokens(text: str) -> set[str]:
    return {word.lower() for word in re.findall(r"[A-Za-z0-9_]{3,}", text or "")}


def _age_minutes(stamp: str) -> float | None:
    if not stamp:
        return None
    try:
        parsed = datetime.fromisoformat(stamp)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return max(0.0, (_now() - parsed).total_seconds() / 60.0)


@dataclass(frozen=True)
class ContextItem:
    """One candidate piece of context with explicit compartment and provenance."""

    id: str
    compartment: str
    content: str
    provenance: str = "unknown"
    source_ref: str = ""
    recorded_at: str = field(default_factory=_iso)
    verified: bool = False
    summarized: bool = False
    pinned: bool = False

    def __post_init__(self) -> None:
        if self.compartment not in COMPARTMENTS:
            raise ValueError(f"Unknown context compartment: {self.compartment}")

    def is_stale(self, *, stale_minutes: float = STALE_CONTEXT_MINUTES) -> bool:
        age = _age_minutes(self.recorded_at)
        return bool(age is not None and age > stale_minutes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "compartment": self.compartment,
            "content": self.content,
            "provenance": self.provenance,
            "source_ref": self.source_ref,
            "recorded_at": self.recorded_at,
            "verified": self.verified,
            "summarized": self.summarized,
            "pinned": self.pinned,
        }


@dataclass(frozen=True)
class StageRecord:
    """One stage of a multi-step task."""

    stage_id: str
    title: str
    status: str
    detail: str
    evidence_ref: str = ""
    completed: bool = False


@dataclass(frozen=True)
class ContextWindow:
    """The assembled, budgeted context ready for a model call or inspection."""

    assembled_at: str
    objective: str
    budget_chars: int
    used_chars: int
    fingerprint: str
    unchanged_since_last_send: bool
    protected: dict[str, list[str]]
    verified_facts: list[dict[str, Any]]
    hypotheses: list[dict[str, Any]]
    stage_summaries: list[str]
    supporting_passages: list[dict[str, Any]]
    selected_items: list[dict[str, Any]]
    dropped_item_ids: list[str]
    requires_source_recheck: bool
    recheck_reasons: list[str]

    def render_prompt_block(self) -> str:
        lines: list[str] = [f"Active objective: {self.objective}"]
        for key in ("constraints", "permissions", "unresolved_blockers", "error_evidence", "critical_decisions", "open_questions"):
            entries = self.protected.get(key) or []
            if entries:
                heading = key.replace("_", " ").capitalize()
                lines.append(f"{heading}: " + " | ".join(entries))
        if self.stage_summaries:
            lines.append("Completed stages (summarized): " + " ; ".join(self.stage_summaries))
        if self.verified_facts:
            lines.append(
                "Verified facts: "
                + " | ".join(f"{item['content']} [{item['source_ref'] or item['provenance']}]" for item in self.verified_facts)
            )
        if self.hypotheses:
            lines.append(
                "Unverified hypotheses (do NOT treat as measured fact): "
                + " | ".join(f"{item['content']} [{item['provenance']}]" for item in self.hypotheses)
            )
        if self.supporting_passages:
            lines.append(
                "Supporting passages: "
                + " | ".join(f"{item['citation']}: {item['text']}" for item in self.supporting_passages)
            )
        if self.requires_source_recheck:
            lines.append("RE-CHECK REQUIRED BEFORE HIGH-IMPACT ACTION: " + "; ".join(self.recheck_reasons))
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "assembled_at": self.assembled_at,
            "objective": self.objective,
            "budget_chars": self.budget_chars,
            "used_chars": self.used_chars,
            "fingerprint": self.fingerprint,
            "unchanged_since_last_send": self.unchanged_since_last_send,
            "protected": self.protected,
            "verified_facts": self.verified_facts,
            "hypotheses": self.hypotheses,
            "stage_summaries": self.stage_summaries,
            "supporting_passages": self.supporting_passages,
            "selected_items": self.selected_items,
            "dropped_item_ids": self.dropped_item_ids,
            "requires_source_recheck": self.requires_source_recheck,
            "recheck_reasons": self.recheck_reasons,
        }


def summarize_stage(stage: StageRecord, *, max_detail_chars: int = 120) -> str:
    """Extractive, deterministic summary of a completed stage (zero model calls)."""
    detail = " ".join((stage.detail or "").split())
    if len(detail) > max_detail_chars:
        detail = detail[:max_detail_chars].rstrip() + "…"
    ref = f" (ref: {stage.evidence_ref})" if stage.evidence_ref else ""
    return f"[{stage.stage_id}:{stage.status}] {stage.title} — {detail}{ref}"


@dataclass
class ContextCache:
    """Tracks fingerprints sent per recipient so identical static blocks are not resent."""

    max_entries: int = 128
    _sent: dict[str, str] = field(default_factory=dict, init=False)
    _cached_windows: dict[str, ContextWindow] = field(default_factory=dict, init=False)
    hits: int = 0
    misses: int = 0

    def check_and_record(self, recipient: str, fingerprint: str, window: ContextWindow) -> bool:
        previous = self._sent.get(recipient)
        unchanged = previous == fingerprint
        if unchanged:
            self.hits += 1
        else:
            self.misses += 1
            if len(self._sent) >= self.max_entries:
                oldest = next(iter(self._sent))
                self._sent.pop(oldest, None)
                self._cached_windows.pop(oldest, None)
            self._sent[recipient] = fingerprint
            self._cached_windows[recipient] = window
        return unchanged

    def invalidate(self, recipient: str = "") -> None:
        if recipient:
            self._sent.pop(recipient, None)
            self._cached_windows.pop(recipient, None)
        else:
            self._sent.clear()
            self._cached_windows.clear()


@dataclass
class ContextOptimizer:
    """Compartmentalized context store + budget-aware context assembler."""

    budget_chars: int = DEFAULT_CONTEXT_BUDGET_CHARS
    stale_minutes: float = STALE_CONTEXT_MINUTES
    redactor: Redactor = field(default_factory=Redactor)
    knowledge_store: KnowledgeStore | None = None
    cache: ContextCache = field(default_factory=ContextCache)
    _compartments: dict[str, list[ContextItem]] = field(
        default_factory=lambda: {name: [] for name in COMPARTMENTS},
        init=False,
    )
    _credential_names: set[str] = field(default_factory=set, init=False)

    def add_item(
        self,
        *,
        item_id: str,
        compartment: str,
        content: str,
        provenance: str = "unknown",
        source_ref: str = "",
        verified: bool | None = None,
        pinned: bool = False,
        recorded_at: str = "",
    ) -> ContextItem:
        if compartment == COMPARTMENT_CREDENTIALS:
            # Credentials are tracked only as opaque key names, never stored as
            # prompt-eligible text.
            self._credential_names.add(item_id)
            return ContextItem(
                id=item_id,
                compartment=COMPARTMENT_CREDENTIALS,
                content="[credential reference stored outside prompt compartments]",
                provenance="system",
                recorded_at=recorded_at or _iso(),
            )
        is_verified = (
            bool(verified)
            if verified is not None
            else (provenance in VERIFIED_PROVENANCES and bool(source_ref or provenance == "user"))
        )
        scrubbed = self.redactor.scrub_text(content, max_chars=4_000)
        item = ContextItem(
            id=item_id,
            compartment=compartment,
            content=scrubbed,
            provenance=provenance,
            source_ref=source_ref,
            recorded_at=recorded_at or _iso(),
            verified=is_verified,
            pinned=pinned,
        )
        bucket = self._compartments[compartment]
        bucket[:] = [existing for existing in bucket if existing.id != item_id]
        bucket.append(item)
        self.cache.invalidate()
        return item

    def register_credential_reference(self, name: str) -> None:
        if name.strip():
            self._credential_names.add(name.strip())

    def compartment_counts(self) -> dict[str, int]:
        counts = {name: len(items) for name, items in self._compartments.items()}
        counts[COMPARTMENT_CREDENTIALS] = len(self._credential_names)
        return counts

    def clear_compartment(self, compartment: str) -> int:
        if compartment not in COMPARTMENTS:
            raise ValueError(f"Unknown compartment: {compartment}")
        if compartment == COMPARTMENT_CREDENTIALS:
            removed = len(self._credential_names)
            self._credential_names.clear()
            return removed
        bucket = self._compartments[compartment]
        removed = len(bucket)
        bucket.clear()
        self.cache.invalidate()
        return removed

    @staticmethod
    def _relevance(query_tokens: set[str], item: ContextItem) -> float:
        if item.pinned:
            return 10.0
        item_tokens = _tokens(item.content) | _tokens(item.source_ref)
        if not query_tokens or not item_tokens:
            return 0.0
        overlap = len(query_tokens & item_tokens)
        if overlap == 0:
            return 0.0
        score = overlap / max(1, min(len(query_tokens), len(item_tokens)))
        if item.verified:
            score += 0.15
        if not item.is_stale():
            score += 0.05
        return round(score, 4)

    def assemble(
        self,
        *,
        objective: str,
        constraints: tuple[str, ...] = (),
        permissions: tuple[str, ...] = (),
        unresolved_blockers: tuple[str, ...] = (),
        error_evidence: tuple[str, ...] = (),
        critical_decisions: tuple[str, ...] = (),
        open_questions: tuple[str, ...] = (),
        stages: tuple[StageRecord, ...] = (),
        project: str = "",
        recipient: str = "primary_model",
        high_impact_action: bool = False,
        budget_chars: int | None = None,
    ) -> ContextWindow:
        cap = max(MIN_CONTEXT_BUDGET_CHARS, int(budget_chars or self.budget_chars))
        protected = {
            "constraints": [self.redactor.scrub_text(x, max_chars=300) for x in constraints if x.strip()],
            "permissions": [self.redactor.scrub_text(x, max_chars=300) for x in permissions if x.strip()],
            "unresolved_blockers": [self.redactor.scrub_text(x, max_chars=300) for x in unresolved_blockers if x.strip()],
            "error_evidence": [self.redactor.scrub_text(x, max_chars=400) for x in error_evidence if x.strip()],
            "critical_decisions": [self.redactor.scrub_text(x, max_chars=300) for x in critical_decisions if x.strip()],
            "open_questions": [self.redactor.scrub_text(x, max_chars=300) for x in open_questions if x.strip()],
        }

        # Protected anchors ALWAYS occupy budget first; nothing may drop them.
        used = len(objective) + sum(sum(len(entry) for entry in entries) for entries in protected.values())

        stage_summaries: list[str] = []
        active_stage_notes: list[ContextItem] = []
        for stage in stages:
            if stage.completed:
                summary = summarize_stage(stage)
                if used + len(summary) <= cap:
                    stage_summaries.append(summary)
                    used += len(summary)
            else:
                active_stage_notes.append(
                    ContextItem(
                        id=f"stage:{stage.stage_id}",
                        compartment=COMPARTMENT_TASK_STATE,
                        content=f"[{stage.stage_id}:{stage.status}] {stage.title}: {stage.detail}",
                        provenance="tool_result" if stage.evidence_ref else "unknown",
                        source_ref=stage.evidence_ref,
                        verified=bool(stage.evidence_ref),
                        pinned=True,
                    )
                )

        query_tokens = _tokens(objective)
        for group in (constraints, unresolved_blockers, open_questions):
            for text in group:
                query_tokens |= _tokens(text)

        supporting_passages: list[dict[str, Any]] = []
        recheck_reasons: list[str] = []
        if self.knowledge_store is not None and objective.strip() and used < cap:
            search_out = self.knowledge_store.search(objective, limit=4, project=project, use_semantic=True)
            for hit in search_out.get("results", []):
                excerpt = self.redactor.scrub_text(str(hit.get("text") or ""), max_chars=360)
                cost = len(excerpt) + len(str(hit.get("citation") or ""))
                if used + cost > cap:
                    break
                prov = hit.get("provenance") or {}
                if prov.get("currency") == CURRENCY_STALE:
                    recheck_reasons.append(f"supporting passage '{hit.get('citation')}' is marked stale")
                supporting_passages.append(
                    {
                        "document_id": hit.get("document_id", ""),
                        "citation": hit.get("citation", ""),
                        "text": excerpt,
                        "source_kind": prov.get("source_kind", ""),
                        "currency": prov.get("currency", ""),
                    }
                )
                used += cost

        # Gather items from all non-credential compartments.
        candidates: list[tuple[float, ContextItem]] = []
        for name, items in self._compartments.items():
            if name == COMPARTMENT_CREDENTIALS:
                continue
            for item in items:
                score = self._relevance(query_tokens, item)
                if score > 0.0:
                    candidates.append((score, item))
        for stage_item in active_stage_notes:
            candidates.append((10.0, stage_item))
        candidates.sort(key=lambda pair: (-pair[0], pair[1].id))

        selected: list[ContextItem] = []
        dropped: list[str] = []
        for _, item in candidates:
            cost = len(item.content) + 32
            if used + cost > cap and not item.pinned:
                dropped.append(item.id)
                continue
            selected.append(item)
            used += cost
            if item.is_stale(stale_minutes=self.stale_minutes):
                recheck_reasons.append(f"context item '{item.id}' is older than {self.stale_minutes:g} minutes")

        # Record irrelevant items that scored 0 as dropped from working context.
        selected_ids = {item.id for item in selected}
        for name, items in self._compartments.items():
            if name == COMPARTMENT_CREDENTIALS:
                continue
            for item in items:
                if item.id not in selected_ids and item.id not in dropped:
                    dropped.append(item.id)

        if high_impact_action and stage_summaries:
            recheck_reasons.append("completed stages were summarized; re-read primary artifacts before high-impact execution")
        if high_impact_action and not any(item.verified for item in selected) and not supporting_passages:
            recheck_reasons.append("no verified facts or source passages are attached for this high-impact action")

        verified_facts = [
            {"id": item.id, "content": item.content, "provenance": item.provenance, "source_ref": item.source_ref}
            for item in selected
            if item.verified
        ]
        hypotheses = [
            {"id": item.id, "content": item.content, "provenance": item.provenance, "source_ref": item.source_ref}
            for item in selected
            if not item.verified
        ]

        digest_source = "|".join(
            [
                objective,
                repr(protected),
                repr(stage_summaries),
                repr([(x["id"], x["content"]) for x in verified_facts]),
                repr([(x["id"], x["content"]) for x in hypotheses]),
                repr([(x["citation"], x["text"]) for x in supporting_passages]),
            ]
        )
        fingerprint = hashlib.sha256(digest_source.encode("utf-8", "replace")).hexdigest()[:24]

        provisional = ContextWindow(
            assembled_at=_iso(),
            objective=objective,
            budget_chars=cap,
            used_chars=used,
            fingerprint=fingerprint,
            unchanged_since_last_send=False,
            protected=protected,
            verified_facts=verified_facts,
            hypotheses=hypotheses,
            stage_summaries=stage_summaries,
            supporting_passages=supporting_passages,
            selected_items=[item.to_dict() for item in selected],
            dropped_item_ids=dropped,
            requires_source_recheck=bool(high_impact_action and recheck_reasons),
            recheck_reasons=recheck_reasons if high_impact_action else [],
        )
        unchanged = self.cache.check_and_record(recipient, fingerprint, provisional)
        if not unchanged:
            return provisional
        return ContextWindow(
            assembled_at=provisional.assembled_at,
            objective=provisional.objective,
            budget_chars=provisional.budget_chars,
            used_chars=provisional.used_chars,
            fingerprint=provisional.fingerprint,
            unchanged_since_last_send=True,
            protected=provisional.protected,
            verified_facts=provisional.verified_facts,
            hypotheses=provisional.hypotheses,
            stage_summaries=provisional.stage_summaries,
            supporting_passages=provisional.supporting_passages,
            selected_items=provisional.selected_items,
            dropped_item_ids=provisional.dropped_item_ids,
            requires_source_recheck=provisional.requires_source_recheck,
            recheck_reasons=provisional.recheck_reasons,
        )


__all__ = [
    "COMPARTMENTS",
    "COMPARTMENT_APPROVED_MEMORY",
    "COMPARTMENT_CONVERSATION",
    "COMPARTMENT_CREDENTIALS",
    "COMPARTMENT_PROJECT_KNOWLEDGE",
    "COMPARTMENT_TASK_STATE",
    "DEFAULT_CONTEXT_BUDGET_CHARS",
    "MIN_CONTEXT_BUDGET_CHARS",
    "STALE_CONTEXT_MINUTES",
    "VERIFIED_PROVENANCES",
    "ContextCache",
    "ContextItem",
    "ContextOptimizer",
    "ContextWindow",
    "StageRecord",
    "summarize_stage",
]
