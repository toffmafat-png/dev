"""§14 Unified Shared Memory and Knowledge System.

Combines SQLite structured memory categories, FTS5 full-text search, and
optional semantic retrieval under one coherent subsystem with:
- 9 distinct storage categories (§14).
- Strict secret rejection/redaction (`NEVER_STORE_SECRETS = True`).
- Epistemic discipline: repeating a model-generated claim never upgrades it to
  `verified_fact = True` (`REPETITION_UPGRADES_FACTUALITY = False`).
- User inspection, correction, export, deletion, retention limits, and
  one-toggle memory disable.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from nova.db import Database
from nova.knowledge import KnowledgeStore
from nova.observability import Redactor

NEVER_STORE_SECRETS = True
REPETITION_UPGRADES_FACTUALITY = False

MEMORY_CATEGORIES: tuple[str, ...] = (
    "conversation_history",
    "user_preferences",
    "ongoing_objectives",
    "project_context",
    "task_state",
    "validated_procedures",
    "retrieved_documents",
    "tool_execution_history",
    "external_information",
)

VERIFIED_PROVENANCES: frozenset[str] = frozenset(
    {"verified_tool_output", "verified_test_result", "user_approved_preference"}
)

_RAW_SECRET_HINT_RE = re.compile(
    r"(?i)(\bsk-[A-Za-z0-9_\-]{12,}\b|\bghp_[A-Za-z0-9]{16,}\b|\bAIza[0-9A-Za-z_\-]{20,}\b|"
    r"\b(?:password|passwd|api[_-]?key|secret[_-]?key|access[_-]?token|private[_-]?key)\s*[:=]\s*\S+)"
)


def _iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


_CATEGORY_TO_SOURCE_KIND: dict[str, str] = {
    "conversation_history": "conversation_history",
    "user_preferences": "user_document",
    "ongoing_objectives": "user_document",
    "project_context": "user_document",
    "task_state": "task_history",
    "validated_procedures": "tool_result",
    "retrieved_documents": "documentation",
    "tool_execution_history": "tool_result",
    "external_information": "external_source",
}


class SharedMemorySystem:
    """§14 Single coherent memory and knowledge facade shared across NOVA X."""

    def __init__(
        self,
        *,
        db: Database,
        knowledge: KnowledgeStore,
        redactor: Redactor | None = None,
        default_retention_per_category: int = 250,
    ) -> None:
        self.db = db
        self.knowledge = knowledge
        self.redactor = redactor or Redactor()
        self._default_retention = max(10, int(default_retention_per_category))

    # ------------------------------------------------- Configuration & Privacy

    def is_enabled(self) -> bool:
        val = self.db.get_desktop_setting("memory_enabled", True)
        return bool(val)

    def set_enabled(self, enabled: bool) -> dict[str, Any]:
        self.db.set_desktop_setting("memory_enabled", bool(enabled))
        return {"memory_enabled": bool(enabled), "updated_at": _iso()}

    def retention_limit(self) -> int:
        raw = self.db.get_desktop_setting("memory_retention_per_category", self._default_retention)
        try:
            return max(5, min(int(raw), 5_000))
        except (TypeError, ValueError):
            return self._default_retention

    def set_retention_limit(self, limit: int) -> dict[str, Any]:
        bounded = max(5, min(int(limit), 5_000))
        self.db.set_desktop_setting("memory_retention_per_category", bounded)
        pruned_total = 0
        for cat in MEMORY_CATEGORIES:
            pruned_total += self.db.prune_memory_category(cat, bounded)
        return {"retention_per_category": bounded, "pruned_entries": pruned_total}

    # ------------------------------------------------- Write / Correct / Delete

    def store(
        self,
        *,
        category: str,
        subject: str,
        content: str,
        provenance: str = "user_stated",
        source_ref: str = "",
        project_id: str = "",
        metadata: dict[str, Any] | None = None,
        evidence_verified: bool = False,
    ) -> dict[str, Any]:
        if category not in MEMORY_CATEGORIES:
            raise ValueError(f"Unsupported memory category '{category}'. Valid: {', '.join(MEMORY_CATEGORIES)}")
        if not self.is_enabled():
            return {"stored": False, "reason": "memory_disabled"}

        # §14 Never store passwords, API keys, or private tokens in ordinary memory.
        if _RAW_SECRET_HINT_RE.search(subject) or _RAW_SECRET_HINT_RE.search(content):
            raise ValueError("Refusing to store credentials, passwords, API keys, or private tokens in memory (§14).")

        clean_subject = self.redactor.scrub_text(subject.strip())
        clean_content = self.redactor.scrub_text(content.strip())
        if "[REDACTED" in clean_subject or "[REDACTED" in clean_content:
            raise ValueError("Refusing to store redacted secret material in ordinary memory (§14).")

        # §14 Do not treat a repeated model-generated claim as a verified fact.
        prov = provenance.strip() or "user_stated"
        is_verified = bool(evidence_verified and prov in VERIFIED_PROVENANCES and prov != "model_generated")

        saved = self.db.save_memory_entry(
            {
                "category": category,
                "subject": clean_subject,
                "content": clean_content,
                "provenance": prov,
                "verified_fact": is_verified,
                "source_ref": self.redactor.scrub_text(source_ref),
                "project_id": project_id,
                "metadata": self.redactor.scrub(metadata or {}),
            }
        )
        # Index into FTS5 KnowledgeStore for fast ranked retrieval.
        self.knowledge.index_text(
            f"{clean_subject}\n{clean_content}",
            document_id=f"mem:{saved['id']}",
            title=f"[{category}] {clean_subject}",
            source_kind=_CATEGORY_TO_SOURCE_KIND.get(category, "user_document"),
            project=project_id,
            external=(category == "external_information"),
            publisher=prov,
        )
        self.db.prune_memory_category(category, self.retention_limit())
        return {"stored": True, "entry": saved}

    def correct_memory(
        self,
        entry_id: str,
        *,
        new_content: str,
        new_subject: str | None = None,
        provenance: str = "user_corrected",
        evidence_verified: bool = False,
    ) -> dict[str, Any]:
        existing = self.db.get_memory_entry(entry_id)
        if existing is None:
            raise KeyError(f"Memory entry '{entry_id}' not found.")
        subj = new_subject.strip() if new_subject else existing["subject"]
        if _RAW_SECRET_HINT_RE.search(subj) or _RAW_SECRET_HINT_RE.search(new_content):
            raise ValueError("Refusing to store credentials or private tokens in memory (§14).")
        clean_content = self.redactor.scrub_text(new_content.strip())
        is_verified = bool(evidence_verified and provenance in VERIFIED_PROVENANCES and provenance != "model_generated")
        meta = dict(existing.get("metadata") or {})
        meta["corrected_at"] = _iso()
        updated = self.db.save_memory_entry(
            {
                **existing,
                "subject": self.redactor.scrub_text(subj),
                "content": clean_content,
                "provenance": provenance,
                "verified_fact": is_verified,
                "metadata": meta,
            }
        )
        self.knowledge.index_text(
            f"{updated['subject']}\n{clean_content}",
            document_id=f"mem:{updated['id']}",
            title=f"[{updated['category']}] {updated['subject']}",
            source_kind=_CATEGORY_TO_SOURCE_KIND.get(str(updated["category"]), "user_document"),
            project=str(updated.get("project_id") or ""),
            external=(updated["category"] == "external_information"),
            publisher=provenance,
        )
        return updated

    def delete_memory(self, entry_id: str) -> bool:
        self.knowledge.remove(f"mem:{entry_id}")
        return self.db.delete_memory_entry(entry_id)

    # ------------------------------------------------- Inspect / Retrieve / Export

    def inspect_memories(self, *, category: str = "", query: str = "", limit: int = 100) -> dict[str, Any]:
        entries = self.db.list_memory_entries(category=category, query=query, limit=limit)
        by_category: dict[str, int] = dict.fromkeys(MEMORY_CATEGORIES, 0)
        for entry in self.db.list_memory_entries(limit=500):
            cat = entry.get("category", "")
            if cat in by_category:
                by_category[cat] += 1
        return {
            "memory_enabled": self.is_enabled(),
            "retention_per_category": self.retention_limit(),
            "fts5_available": self.knowledge.fts_available,
            "categories": list(MEMORY_CATEGORIES),
            "counts_by_category": by_category,
            "entries": entries,
        }

    def retrieve_relevant_context(self, query: str, *, max_chars: int = 1_600, limit: int = 6) -> dict[str, Any]:
        """§14 Retrieve compact FTS5/hybrid-ranked context instead of dumping every saved conversation."""
        if not self.is_enabled() or not query.strip():
            return {"enabled": self.is_enabled(), "snippets": [], "formatted_context": ""}
        search_res = self.knowledge.search(query.strip(), limit=limit)
        hits = list(search_res.get("results") or [])
        snippets: list[dict[str, Any]] = []
        lines: list[str] = []
        used = 0
        for hit in hits:
            text = str(hit.get("text") or "").strip()
            doc_id = str(hit.get("document_id") or "")
            title = str(hit.get("title") or doc_id or "memory")
            verified = False
            prov = str((hit.get("provenance") or {}).get("publisher") or (hit.get("provenance") or {}).get("source_kind") or "indexed")
            if doc_id.startswith("mem:"):
                mem_row = self.db.get_memory_entry(doc_id.removeprefix("mem:"))
                if mem_row is not None:
                    prov = mem_row["provenance"]
                    verified = bool(mem_row["verified_fact"])
            tag = "verified" if verified else f"unverified:{prov}"
            line = f"- {title} [{tag}]: {text[:260]}"
            if used + len(line) > max_chars:
                break
            lines.append(line)
            snippets.append({"document_id": doc_id, "title": title, "provenance": prov, "verified_fact": verified, "snippet": text[:260]})
            used += len(line)
        return {
            "enabled": True,
            "retrieval_mode": "fts5_first",
            "snippets": snippets,
            "formatted_context": "\n".join(lines),
        }

    def export_memories(self) -> dict[str, Any]:
        entries = self.db.list_memory_entries(limit=500)
        procedures = self.db.list_cognition_procedures()
        goals = self.db.list_goals()
        return {
            "exported_at": _iso(),
            "memory_enabled": self.is_enabled(),
            "retention_per_category": self.retention_limit(),
            "entries": entries,
            "validated_cognition_procedures": [p for p in procedures if p.get("status") == "established"],
            "ongoing_goals": goals,
        }
